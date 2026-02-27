"""Rich console reporter for terminal display."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from medusa.core.models import ScanResult, Severity, Status
from medusa.reporters.base import BaseReporter

GRADE_COLORS = {
    "A": "green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "red",
}

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFORMATIONAL: "dim",
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


class ConsoleReporter(BaseReporter):
    """Rich terminal output for scan results."""

    def generate(self, result: ScanResult) -> str:
        """Plain-text fallback for non-TTY contexts."""
        return (
            f"Grade: {result.aggregate_grade} ({result.aggregate_score}/10) | "
            f"{result.total_findings} findings | "
            f"{result.servers_scanned} server(s) in {result.scan_duration_seconds}s"
        )

    def print_to_console(self, result: ScanResult, console: Console) -> None:
        """Render a rich formatted scan report to the terminal."""
        self._print_header(result, console)
        self._print_grade(result, console)
        self._print_severity_summary(result, console)
        self._print_server_breakdown(result, console)
        self._print_findings_table(result, console)
        self._print_status_counts(result, console)
        if result.compliance_results:
            self._print_compliance(result, console)
        self._print_footer(result, console)

    def _print_header(self, result: ScanResult, console: Console) -> None:
        console.print()
        console.print(Rule("SCAN RESULTS", style="bold"))
        ts = result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        console.print(
            f"  [dim]Scan ID: {result.scan_id}  |  {ts}  |  "
            f"Medusa v{result.medusa_version}[/dim]"
        )
        console.print()

    def _print_grade(self, result: ScanResult, console: Console) -> None:
        color = GRADE_COLORS.get(result.aggregate_grade, "white")
        grade_text = Text(justify="center")
        grade_text.append(f"{result.aggregate_grade}\n", style=f"bold {color}")
        grade_text.append(f"{result.aggregate_score} / 10", style=color)
        panel = Panel(
            grade_text,
            title="Overall Grade",
            border_style=color,
            padding=(1, 4),
        )
        console.print(panel)

    def _print_severity_summary(self, result: ScanResult, console: Console) -> None:
        failed = [f for f in result.findings if f.status == Status.FAIL]
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in failed:
            counts[f.severity] += 1
        parts = []
        if counts[Severity.CRITICAL]:
            parts.append(f"[bold red]{counts[Severity.CRITICAL]} Critical[/]")
        if counts[Severity.HIGH]:
            parts.append(f"[red]{counts[Severity.HIGH]} High[/]")
        if counts[Severity.MEDIUM]:
            parts.append(f"[yellow]{counts[Severity.MEDIUM]} Medium[/]")
        if counts[Severity.LOW]:
            parts.append(f"[blue]{counts[Severity.LOW]} Low[/]")
        if counts[Severity.INFORMATIONAL]:
            parts.append(f"[dim]{counts[Severity.INFORMATIONAL]} Info[/]")
        if parts:
            console.print(f"  {' · '.join(parts)}")
        console.print()

    def _print_server_breakdown(self, result: ScanResult, console: Console) -> None:
        console.print(Rule("Server Breakdown"))
        console.print()
        for ss in result.server_scores:
            color = GRADE_COLORS.get(ss.grade, "white")
            body = (
                f"  Score: [bold]{ss.score}/10[/]  Grade: [{color}]{ss.grade}[/{color}]\n"
                f"  Passed: [green]{ss.passed}[/]  Failed: [red]{ss.failed}[/]\n"
                f"  [bold red]{ss.critical_findings}[/] Critical  ·  "
                f"[red]{ss.high_findings}[/] High  ·  "
                f"[yellow]{ss.medium_findings}[/] Medium  ·  "
                f"[blue]{ss.low_findings}[/] Low"
            )
            console.print(
                Panel(body, title=f"[bold]{ss.server_name}[/]", border_style=color)
            )
        console.print()

    def _print_findings_table(self, result: ScanResult, console: Console) -> None:
        failed = [f for f in result.findings if f.status == Status.FAIL]
        failed.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        console.print(Rule(f"Failed Findings ({len(failed)})"))
        console.print()

        if not failed:
            console.print("  [green]No failed findings. All checks passed![/]")
            console.print()
            return

        table = Table(show_header=True, header_style="bold", show_lines=False)
        table.add_column("Severity", width=10)
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Title", max_width=40, overflow="ellipsis")
        table.add_column("Server")
        table.add_column("Resource", max_width=25, overflow="ellipsis")
        table.add_column("OWASP")

        for f in failed:
            sev_style = SEVERITY_STYLES.get(f.severity, "")
            owasp = ", ".join(f.owasp_mcp) if f.owasp_mcp else "-"
            resource = f"{f.resource_type}/{f.resource_name}"
            table.add_row(
                f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]",
                f.check_id,
                f.check_title,
                f.server_name,
                resource,
                owasp,
            )

        console.print(table)
        console.print()

    def _print_status_counts(self, result: ScanResult, console: Console) -> None:
        passed = sum(1 for f in result.findings if f.status == Status.PASS)
        skipped = sum(1 for f in result.findings if f.status == Status.SKIPPED)
        errors = sum(1 for f in result.findings if f.status == Status.ERROR)
        console.print(
            f"  [green]{passed}[/] passed  ·  "
            f"[dim]{skipped}[/] skipped  ·  "
            f"[red]{errors}[/] errors"
        )
        console.print()

    def _print_compliance(self, result: ScanResult, console: Console) -> None:
        console.print(Rule("Compliance"))
        console.print()
        for framework_name, requirements in result.compliance_results.items():
            console.print(f"  [bold]{framework_name}[/]")
            if isinstance(requirements, dict):
                for req_name, req_data in requirements.items():
                    if isinstance(req_data, dict):
                        status = req_data.get("status", "unknown")
                        style = "green" if status == "pass" else "red"
                        console.print(f"    [{style}]{status.upper()}[/{style}]  {req_name}")
                    else:
                        console.print(f"    {req_name}: {req_data}")
            console.print()

    def _print_footer(self, result: ScanResult, console: Console) -> None:
        console.print(Rule())
        console.print(
            f"  Scanned {result.servers_scanned} server(s) in "
            f"{result.scan_duration_seconds}s"
        )
        console.print()
