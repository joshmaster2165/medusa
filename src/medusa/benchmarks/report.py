"""Benchmark report generators (console + markdown)."""
from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from medusa.benchmarks.models import BenchmarkReport


def _grade_color(grade: str) -> str:
    """Return Rich color for a grade letter."""
    return {
        "A": "green",
        "B": "cyan",
        "C": "yellow",
        "D": "dark_orange",
        "F": "red",
    }.get(grade, "white")


def print_benchmark_report(report: BenchmarkReport, console: Console | None = None) -> None:
    """Print a benchmark report to the console using Rich tables."""
    if console is None:
        console = Console()

    console.print()
    console.print("[bold]Medusa Benchmark Report[/bold]")
    console.print(f"Timestamp: {report.timestamp}")
    console.print(
        f"Servers: {report.scanned_servers} scanned, "
        f"{report.skipped_servers} skipped, "
        f"{report.total_servers} total"
    )
    console.print(f"Average Score: [bold]{report.average_score}/10.0[/bold]")
    console.print()

    # Results table
    table = Table(title="Server Benchmark Results", show_lines=True)
    table.add_column("Server", style="bold")
    table.add_column("Package")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")
    table.add_column("Tools", justify="right")
    table.add_column("Pass", justify="right", style="green")
    table.add_column("Fail", justify="right", style="red")
    table.add_column("Critical", justify="right")
    table.add_column("High", justify="right")

    for r in report.results:
        if r.status == "scanned":
            color = _grade_color(r.grade)
            table.add_row(
                r.server_name,
                r.package,
                "[green]scanned[/green]",
                f"{r.score:.1f}",
                f"[{color}]{r.grade}[/{color}]",
                str(r.tool_count),
                str(r.passed),
                str(r.failed),
                str(r.critical_findings) if r.critical_findings else "-",
                str(r.high_findings) if r.high_findings else "-",
            )
        elif r.status == "skipped":
            table.add_row(
                r.server_name,
                r.package,
                "[yellow]skipped[/yellow]",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                f"[dim]{r.skip_reason}[/dim]",
            )
        else:
            table.add_row(
                r.server_name,
                r.package,
                "[red]error[/red]",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                f"[dim]{r.error_message[:50]}[/dim]",
            )

    console.print(table)

    # Top findings for each scanned server
    for r in report.results:
        if r.status == "scanned" and r.top_findings:
            console.print(f"\n[bold]{r.server_name}[/bold] top findings:")
            for f in r.top_findings:
                console.print(f"  - {f}")


def generate_markdown_report(report: BenchmarkReport) -> str:
    """Generate a Markdown benchmark report."""
    lines = [
        "# Medusa Benchmark Report",
        "",
        f"**Date:** {report.timestamp}",
        f"**Servers:** {report.scanned_servers} scanned, {report.skipped_servers} skipped",
        f"**Average Score:** {report.average_score}/10.0",
        "",
        "## Results",
        "",
        "| Server | Package | Status | Score | Grade | Tools | Pass | Fail | Critical | High |",
        "|--------|---------|--------|-------|-------|-------|------|------|----------|------|",
    ]

    for r in report.results:
        if r.status == "scanned":
            lines.append(
                f"| {r.server_name} | {r.package} | {r.status} "
                f"| {r.score:.1f} | {r.grade} "
                f"| {r.tool_count} | {r.passed} | {r.failed} "
                f"| {r.critical_findings} | {r.high_findings} |"
            )
        elif r.status == "skipped":
            lines.append(
                f"| {r.server_name} | {r.package} "
                f"| skipped | - | - | - | - | - "
                f"| - | {r.skip_reason} |"
            )
        else:
            msg = r.error_message[:50]
            lines.append(
                f"| {r.server_name} | {r.package} "
                f"| error | - | - | - | - | - "
                f"| - | {msg} |"
            )

    lines.append("")
    lines.append("## Top Findings by Server")
    lines.append("")
    for r in report.results:
        if r.status == "scanned" and r.top_findings:
            lines.append(f"### {r.server_name}")
            for f in r.top_findings:
                lines.append(f"- {f}")
            lines.append("")

    return "\n".join(lines)


def save_benchmark_results(report: BenchmarkReport, output_dir: str = "benchmarks/results") -> Path:
    """Save benchmark results to JSON."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Use timestamp for filename
    timestamp = report.timestamp.replace(":", "-").replace("+", "_")
    filepath = out_path / f"{timestamp}.json"
    filepath.write_text(report.model_dump_json(indent=2))
    return filepath
