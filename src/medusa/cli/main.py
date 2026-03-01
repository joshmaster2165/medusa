"""Medusa CLI entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

import click
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from medusa import __version__
from medusa.cli.banner import print_banner
from medusa.compliance.framework import evaluate_compliance, load_framework
from medusa.connectors.config_discovery import discover_servers
from medusa.connectors.http import HttpConnector
from medusa.connectors.stdio import StdioConnector
from medusa.core.registry import CheckRegistry
from medusa.core.scanner import ScanEngine, has_findings_above_threshold
from medusa.reporters.console_reporter import ConsoleReporter
from medusa.reporters.html_reporter import HtmlReporter
from medusa.reporters.json_reporter import JsonReporter
from medusa.reporters.markdown_reporter import MarkdownReporter
from medusa.reporters.sarif_reporter import SarifReporter
from medusa.utils.config_parser import load_config

console = Console()
logger = logging.getLogger(__name__)


# ── Help text formatters ─────────────────────────────────────────────────


class _OrderedGroup(click.Group):
    """Click group that preserves command insertion order in --help."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        return list(self.commands)


EPILOG = """
\b
Quick start:
  medusa scan --http http://localhost:3000/mcp
  medusa scan --http http://localhost:3000/mcp --ai
  medusa scan --http http://localhost:3000/mcp --all
  medusa scan --http http://localhost:3000/mcp --upload
  medusa scan -o html --output-file report.html
  medusa configure
  medusa settings

Docs: https://medusa.security/docs
"""


# ── CLI group ─────────────────────────────────────────────────────────────


@click.group(
    cls=_OrderedGroup,
    invoke_without_command=True,
    epilog=EPILOG,
)
@click.version_option(version=__version__, prog_name="medusa")
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (-v, -vv, -vvv).",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="Suppress output except errors.",
)
@click.pass_context
def cli(ctx: click.Context, verbose: int, quiet: bool) -> None:
    """Medusa — Security scanner for MCP servers.

    Scans Model Context Protocol (MCP) servers for security vulnerabilities
    using 435+ static checks and optional AI-powered analysis.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet

    if not quiet:
        print_banner(console, __version__)

    # Show help if no subcommand provided
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())

    level = logging.WARNING
    if quiet:
        level = logging.ERROR
    elif verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
    )


# ── scan ──────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--http",
    "http_url",
    type=str,
    default=None,
    help="HTTP/SSE MCP server URL to scan.",
)
@click.option(
    "--stdio",
    "stdio_cmd",
    type=str,
    default=None,
    help="Stdio MCP server command to scan.",
)
@click.option(
    "--config-file",
    type=str,
    default=None,
    help="Path to MCP client config (claude_desktop_config.json, etc).",
)
@click.option(
    "--scan-config",
    type=str,
    default=None,
    help="Path to medusa.yaml scan configuration.",
)
@click.option(
    "--server",
    type=str,
    default=None,
    help="Name of a specific server from config to scan.",
)
@click.option(
    "--no-auto-discover",
    is_flag=True,
    help="Disable automatic server discovery.",
)
@click.option(
    "-o",
    "--output",
    "output_format",
    type=click.Choice(["console", "json", "html", "markdown", "sarif"]),
    default="console",
    help="Report format.  [default: console]",
)
@click.option(
    "--output-file",
    type=str,
    default=None,
    help="Write report to file instead of stdout.",
)
@click.option(
    "--category",
    type=str,
    default=None,
    help="Only run checks in these categories (comma-separated).",
)
@click.option(
    "--severity",
    type=str,
    default=None,
    help="Minimum severity to include in results.",
)
@click.option(
    "--checks",
    type=str,
    default=None,
    help="Only run these check IDs (comma-separated).",
)
@click.option(
    "--exclude-checks",
    type=str,
    default=None,
    help="Skip these check IDs (comma-separated).",
)
@click.option(
    "--fail-on",
    type=str,
    default="high",
    help="Exit code 1 if findings at or above this severity.  [default: high]",
)
@click.option(
    "--compliance",
    type=str,
    default=None,
    help="Evaluate a compliance framework (e.g. owasp_mcp_top10).",
)
@click.option(
    "--max-concurrency",
    type=int,
    default=4,
    help="Max parallel server scans.  [default: 4]",
)
@click.option(
    "--upload",
    is_flag=True,
    default=False,
    help="Upload results to your Medusa dashboard.",
)
@click.option(
    "--api-key",
    type=str,
    default=None,
    help="Medusa API key (overrides env/config).",
)
@click.option(
    "--static",
    "flag_static",
    is_flag=True,
    default=False,
    help="Run static checks only (default behavior).",
)
@click.option(
    "--ai",
    "flag_ai",
    is_flag=True,
    default=False,
    help="Run AI analysis only (requires Claude API key).",
)
@click.option(
    "--all",
    "flag_all",
    is_flag=True,
    default=False,
    help="Run both static checks and AI analysis.",
)
@click.option(
    "--claude-api-key",
    type=str,
    default=None,
    help="Anthropic API key for AI analysis (overrides env/config).",
)
@click.option(
    "--ai-mode",
    type=click.Choice(["byok", "proxied"]),
    default=None,
    help="AI key mode: bring your own key or use dashboard proxy.",
)
@click.pass_context
def scan(  # noqa: C901, PLR0912, PLR0913
    ctx: click.Context,
    config_file: str | None,
    scan_config: str | None,
    http_url: str | None,
    stdio_cmd: str | None,
    server: str | None,
    output_format: str,
    output_file: str | None,
    category: str | None,
    severity: str | None,
    checks: str | None,
    exclude_checks: str | None,
    fail_on: str,
    compliance: str | None,
    no_auto_discover: bool,
    max_concurrency: int,
    upload: bool,
    api_key: str | None,
    flag_static: bool,
    flag_ai: bool,
    flag_all: bool,
    claude_api_key: str | None,
    ai_mode: str | None,
) -> None:
    """Scan MCP servers for security vulnerabilities.

    Run 435+ static security checks against your MCP servers. Use --ai for
    AI-only analysis or --all for both static + AI combined.

    \b
    Scan modes (mutually exclusive):
      --static   Static checks only (default)
      --ai       AI analysis only (requires Claude key + credits)
      --all      Both static checks and AI analysis

    \b
    Examples:
      medusa scan --http http://localhost:3000/mcp
      medusa scan --http http://localhost:3000/mcp --ai
      medusa scan --http http://localhost:3000/mcp --all
      medusa scan --config-file ~/.cursor/mcp.json
      medusa scan -o html --output-file report.html
    """
    quiet = ctx.obj.get("quiet", False)

    # ── Resolve scan mode ─────────────────────────────────────────
    mode_flags = [flag_static, flag_ai, flag_all]
    if sum(mode_flags) > 1:
        console.print(
            "\n  [red]Use only one of --static, --ai, or --all.[/red]"
        )
        sys.exit(2)

    if flag_ai:
        scan_mode = "ai"
    elif flag_all:
        scan_mode = "full"
    else:
        scan_mode = "static"

    # Load scan config
    config = load_config(scan_config)

    # Build connectors
    connectors = []

    # Explicit server targets
    if http_url:
        connectors.append(HttpConnector(name="cli-http", url=http_url))
    if stdio_cmd:
        parts = stdio_cmd.split()
        connectors.append(
            StdioConnector(
                name="cli-stdio",
                command=parts[0],
                args=parts[1:],
            )
        )

    # Config file discovery
    extra_configs = []
    if config_file:
        extra_configs.append(config_file)
    extra_configs.extend(config.discovery.config_files)

    # Auto-discover from known config locations
    has_explicit = http_url or stdio_cmd
    if not no_auto_discover and config.discovery.auto_discover and not has_explicit:
        discovered = discover_servers(additional_config_files=extra_configs)
        connectors.extend(discovered)
    elif extra_configs:
        discovered = discover_servers(additional_config_files=extra_configs)
        connectors.extend(discovered)

    # Servers from medusa.yaml
    for srv in config.discovery.servers:
        if srv.transport == "http" and srv.url:
            connectors.append(
                HttpConnector(
                    name=srv.name,
                    url=srv.url,
                    headers=srv.headers,
                )
            )
        elif srv.transport == "stdio" and srv.command:
            connectors.append(
                StdioConnector(
                    name=srv.name,
                    command=srv.command,
                    args=srv.args,
                    env=srv.env,
                )
            )

    if not connectors:
        if not quiet:
            console.print()
            console.print(
                Panel(
                    "[yellow]No MCP servers found to scan.[/yellow]\n\n"
                    "Specify a target:\n"
                    "  [cyan]medusa scan --http[/cyan] http://localhost:3000/mcp\n"
                    "  [cyan]medusa scan --stdio[/cyan] 'npx my-mcp-server'\n"
                    "  [cyan]medusa scan --config-file[/cyan] ~/.cursor/mcp.json\n\n"
                    "Or enable auto-discovery by placing a [bold]medusa.yaml[/bold] "
                    "in your project root.",
                    title="[bold yellow]No Targets[/bold yellow]",
                    border_style="yellow",
                    padding=(1, 2),
                )
            )
        sys.exit(3)

    if not quiet:
        server_word = "server" if len(connectors) == 1 else "servers"
        names = ", ".join(c.name for c in connectors[:5])
        if len(connectors) > 5:
            names += f" (+{len(connectors) - 5} more)"
        console.print(
            f"  [green]▸ Found {len(connectors)} {server_word}:[/green] "
            f"[dim]{names}[/dim]"
        )

    # Discover and filter checks
    registry = CheckRegistry()
    registry.discover_checks()

    categories = category.split(",") if category else None
    check_ids = checks.split(",") if checks else None
    exclude_ids = exclude_checks.split(",") if exclude_checks else None
    # Merge excludes from config
    config_excludes = config.checks.exclude
    if config_excludes:
        if exclude_ids:
            exclude_ids.extend(config_excludes)
        else:
            exclude_ids = config_excludes

    # ── AI scanning setup ─────────────────────────────────────────
    if scan_mode in ("ai", "full"):
        _setup_ai_scan(
            ctx, ai_mode, claude_api_key, api_key, quiet
        )
        # Single credit deduction for the entire AI scan
        if not _deduct_ai_scan_credit(quiet):
            sys.exit(2)

    # Build the scan engine
    engine = ScanEngine(
        connectors=connectors,
        registry=registry,
        categories=categories,
        check_ids=check_ids,
        exclude_ids=exclude_ids,
        max_concurrency=max_concurrency,
        scan_mode=scan_mode,
    )

    num_checks = len(engine.checks)
    total_work = len(connectors) * num_checks

    if not quiet:
        check_word = "check" if num_checks == 1 else "checks"
        if scan_mode == "ai":
            # AI mode: show category count + total static checks covered
            ai_count = num_checks
            static_covered = sum(
                1
                for c in registry.get_checks()
                if not c.metadata().check_id.startswith("ai")
            )
            console.print(
                f"  [green]▸ Running {ai_count} AI {check_word}[/green] "
                f"[dim]({ai_count} categories · {static_covered}+ checks "
                f"covered)[/dim]"
            )
        elif scan_mode == "full":
            ai_count = sum(
                1
                for c in engine.checks
                if c.metadata().check_id.startswith("ai")
            )
            static_count = num_checks - ai_count
            console.print(
                f"  [green]▸ Running {num_checks} {check_word}[/green] "
                f"[dim]({static_count} static + {ai_count} AI categories)"
                f"[/dim]"
            )
        else:
            console.print(
                f"  [green]▸ Running {num_checks} {check_word}[/green] "
                f"[dim](static)[/dim]"
            )
        console.print()

    # Run scan with progress bar
    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        disable=quiet,
    ) as progress:
        task = progress.add_task("Scanning...", total=total_work)

        def on_progress(event: str, detail: str) -> None:
            if event == "check_done":
                progress.update(task, advance=1)
            elif event == "server_start":
                progress.update(
                    task,
                    description=f"Scanning [cyan]{detail}[/cyan]...",
                )

        engine.progress_callback = on_progress
        result = asyncio.run(engine.scan())

    # Evaluate compliance if requested
    compliance_name = compliance or (
        config.compliance.frameworks[0] if config.compliance.frameworks else None
    )
    if compliance_name:
        try:
            framework = load_framework(compliance_name)
            result.compliance_results[framework.name] = evaluate_compliance(
                framework, result.findings
            )
        except FileNotFoundError:
            if not quiet:
                console.print(
                    f"[yellow]⚠ Compliance framework not found: "
                    f"{compliance_name}[/yellow]"
                )

    # Generate report
    reporters = {
        "console": ConsoleReporter,
        "json": JsonReporter,
        "html": HtmlReporter,
        "markdown": MarkdownReporter,
        "sarif": SarifReporter,
    }

    # Smart default: fall back to JSON when piped (stdout not a TTY)
    effective_format = output_format
    if output_format == "console" and not sys.stdout.isatty() and not output_file:
        effective_format = "json"

    reporter = reporters[effective_format]()

    if output_file:
        # Console reporter cannot write to file; fall back to JSON
        if effective_format == "console":
            reporter = JsonReporter()
        reporter.write(result, output_file)
        if not quiet:
            console.print(f"  [green]▸ Report saved:[/green] {output_file}")
    else:
        reporter.print_to_console(result, console)

    # Upload results to dashboard
    if upload:
        _upload_results(result, api_key, quiet)

    # Print summary for non-console formats (console reporter includes its own)
    if not quiet and effective_format != "console":
        console.print()
        _print_summary(result)

    # Exit code
    if has_findings_above_threshold(result, fail_on):
        sys.exit(1)


# ── AI setup ──────────────────────────────────────────────────────────────


def _setup_ai_scan(
    ctx: click.Context,
    ai_mode: str | None,
    claude_api_key: str | None,
    api_key: str | None,
    quiet: bool,
) -> None:
    """Configure the AI client and credit manager for AI scanning."""
    from medusa.ai.client import (
        BackendProxiedClient,
        ClaudeClient,
        configure_ai,
    )
    from medusa.ai.credits import CreditManager
    from medusa.cli.config import load_user_config

    user_config = load_user_config()

    # Determine AI mode: flag > config > default
    mode = ai_mode or user_config.ai_mode or "byok"

    # Resolve Medusa API key (needed for credits in both modes)
    medusa_key = (
        api_key
        or os.environ.get("MEDUSA_API_KEY", "")
        or (user_config.api_key or "")
    )

    if mode == "byok":
        # Resolve Claude API key: flag > env > config
        resolved_claude_key = (
            claude_api_key
            or os.environ.get("ANTHROPIC_API_KEY", "")
            or (user_config.claude_api_key or "")
        )
        if not resolved_claude_key:
            console.print()
            console.print(
                Panel(
                    "[red]Claude API key required for AI scanning.[/red]\n\n"
                    "Provide one of:\n"
                    "  [cyan]--claude-api-key[/cyan] sk-ant-...\n"
                    "  [cyan]ANTHROPIC_API_KEY[/cyan] environment variable\n"
                    "  [cyan]medusa configure[/cyan] to save it\n\n"
                    "Or use [cyan]--ai-mode proxied[/cyan] to route through "
                    "your Medusa dashboard.",
                    title="[bold red]Missing API Key[/bold red]",
                    border_style="red",
                    padding=(1, 2),
                )
            )
            sys.exit(2)

        client = ClaudeClient(
            api_key=resolved_claude_key,
            model=user_config.claude_model,
        )
    else:
        # Proxied mode — dashboard holds the Anthropic key
        if not medusa_key:
            console.print()
            console.print(
                Panel(
                    "[red]Medusa API key required for proxied AI scanning.[/red]\n\n"
                    "Run [cyan]medusa configure[/cyan] to set your API key,\n"
                    "or pass [cyan]--api-key[/cyan] directly.",
                    title="[bold red]Missing API Key[/bold red]",
                    border_style="red",
                    padding=(1, 2),
                )
            )
            sys.exit(2)

        client = BackendProxiedClient(
            medusa_api_key=medusa_key,
            dashboard_url=user_config.dashboard_url,
        )

    # Set up credit manager (needs Medusa API key)
    credit_mgr = None
    if medusa_key:
        credit_mgr = CreditManager(
            api_key=medusa_key,
            dashboard_url=user_config.dashboard_url,
        )

    configure_ai(client=client, credit_manager=credit_mgr)

    if not quiet:
        mode_label = "BYOK" if mode == "byok" else "Proxied"
        console.print(
            f"  [bright_magenta]▸ AI analysis enabled[/bright_magenta] "
            f"[dim]({mode_label} mode)[/dim]"
        )


def _deduct_ai_scan_credit(quiet: bool) -> bool:
    """Deduct a single credit for the entire AI scan.

    Credits are deducted once per scan, not per-check.
    Returns True if the scan should proceed, False to abort.
    """
    try:
        from medusa.ai.client import get_credit_manager

        credit_mgr = get_credit_manager()
    except Exception:
        # No credit manager configured (e.g. BYOK without Medusa key)
        # — allow the scan, user pays via their own API key
        return True

    async def _deduct() -> bool:
        return await credit_mgr.deduct(
            check_id="ai_scan",
            server_name="*",
            scan_id="",
        )

    try:
        ok = asyncio.run(_deduct())
        if not ok:
            if not quiet:
                console.print()
                console.print(
                    Panel(
                        "[red]Insufficient AI credits.[/red]\n\n"
                        "Purchase more credits at your Medusa dashboard,\n"
                        "or use [cyan]--static[/cyan] for static-only scanning.",
                        title="[bold red]No Credits[/bold red]",
                        border_style="red",
                        padding=(1, 2),
                    )
                )
            return False
        return True
    except Exception as e:
        logger.warning(
            "Credit deduction failed: %s — continuing anyway", e
        )
        return True


# ── Upload ────────────────────────────────────────────────────────────────


def _upload_results(result, api_key: str | None, quiet: bool) -> None:
    """Upload scan results to the Medusa dashboard."""
    from medusa.cli.config import load_user_config

    user_config = load_user_config()
    upload_url = user_config.dashboard_url

    # Resolve API key: --api-key flag > env var > saved config
    resolved_key = (
        api_key
        or os.environ.get("MEDUSA_API_KEY", "")
        or (user_config.api_key or "")
    )

    if not resolved_key:
        console.print()
        console.print(
            Panel(
                "[red]API key required for upload.[/red]\n\n"
                "Provide one of:\n"
                "  [cyan]--api-key[/cyan] sk_medusa_...\n"
                "  [cyan]MEDUSA_API_KEY[/cyan] environment variable\n"
                "  [cyan]medusa configure[/cyan] to save it",
                title="[bold red]Upload Failed[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        sys.exit(2)

    if not quiet:
        console.print("\n  [dim]Uploading results to dashboard...[/dim]")

    try:
        resp = httpx.post(
            upload_url,
            json=result.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {resolved_key}"},
            timeout=30,
        )
        if resp.status_code == 200:
            if not quiet:
                # Build dashboard base from upload endpoint
                if "/api/" in upload_url:
                    dash = upload_url.rsplit("/api/", 1)[0]
                else:
                    dash = upload_url
                console.print(
                    f"  [green]▸ Uploaded to dashboard:[/green] "
                    f"[dim]{dash}[/dim]"
                )
        else:
            try:
                detail = resp.json().get("error", resp.text)
            except (ValueError, KeyError):
                detail = resp.text[:200] or f"HTTP {resp.status_code}"
            console.print(
                f"  [red]✗ Upload failed ({resp.status_code}):[/red] {detail}"
            )
    except httpx.HTTPError as exc:
        console.print(f"  [red]✗ Upload failed:[/red] {exc}")


# ── Summary ───────────────────────────────────────────────────────────────


def _print_summary(result) -> None:
    """Print a summary table to the console."""
    grade_colors = {
        "A": "green",
        "B": "green",
        "C": "yellow",
        "D": "red",
        "F": "red",
    }
    color = grade_colors.get(result.aggregate_grade, "white")

    grade = result.aggregate_grade
    score = result.aggregate_score
    console.print(f"[bold {color}]Grade: {grade} ({score}/10)[/bold {color}]")
    console.print()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Server")
    table.add_column("Score")
    table.add_column("Grade")
    table.add_column("Critical", style="red")
    table.add_column("High", style="yellow")
    table.add_column("Medium")
    table.add_column("Low", style="blue")

    for ss in result.server_scores:
        scolor = grade_colors.get(ss.grade, "white")
        table.add_row(
            ss.server_name,
            f"{ss.score}/10",
            f"[{scolor}]{ss.grade}[/{scolor}]",
            str(ss.critical_findings),
            str(ss.high_findings),
            str(ss.medium_findings),
            str(ss.low_findings),
        )

    console.print(table)
    console.print()
    duration = result.scan_duration_seconds
    servers = result.servers_scanned
    server_word = "server" if servers == 1 else "servers"
    console.print(f"  Scanned {servers} {server_word} in {duration}s")


# ── list-checks ───────────────────────────────────────────────────────────


@cli.command("list-checks")
@click.option(
    "--category",
    type=str,
    default=None,
    help="Filter by category.",
)
@click.option(
    "--severity",
    type=str,
    default=None,
    help="Filter by severity.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format.",
)
def list_checks(category: str | None, severity: str | None, fmt: str) -> None:
    """List all available security checks.

    Browse and filter the full check catalog. Use --category or --severity
    to narrow results. AI-powered checks are marked with [AI].

    \b
    Examples:
      medusa list-checks
      medusa list-checks --category tool_poisoning
      medusa list-checks --severity critical --format json
    """
    registry = CheckRegistry()
    registry.discover_checks()

    categories = [category] if category else None
    severities = [severity] if severity else None
    all_checks = registry.get_checks(categories=categories, severities=severities)

    if fmt == "json":
        import json

        data = [
            {
                "check_id": c.metadata().check_id,
                "title": c.metadata().title,
                "category": c.metadata().category,
                "severity": c.metadata().severity.value,
                "owasp_mcp": c.metadata().owasp_mcp,
            }
            for c in all_checks
        ]
        click.echo(json.dumps(data, indent=2))
        return

    # Count static vs AI
    static = [c for c in all_checks if not c.metadata().check_id.startswith("ai")]
    ai = [c for c in all_checks if c.metadata().check_id.startswith("ai")]

    title = f"Medusa Security Checks — {len(static)} static"
    if ai:
        title += f" + {len(ai)} AI"

    table = Table(
        title=title,
        show_header=True,
        title_style="bold",
    )
    table.add_column("ID", style="cyan", width=8)
    table.add_column("Title")
    table.add_column("Category", style="magenta")
    table.add_column("Severity", width=12)
    table.add_column("OWASP MCP")

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "informational": "dim",
    }

    for check in all_checks:
        meta = check.metadata()
        sev_style = severity_styles.get(meta.severity.value, "")
        owasp = ", ".join(meta.owasp_mcp) if meta.owasp_mcp else "-"
        # Mark AI checks with a badge
        title_display = meta.title
        if meta.check_id.startswith("ai"):
            title_display = f"[bright_magenta]●[/bright_magenta] {meta.title}"
        table.add_row(
            meta.check_id,
            title_display,
            meta.category,
            f"[{sev_style}]{meta.severity.value}[/{sev_style}]",
            owasp,
        )

    console.print(table)


# ── configure ─────────────────────────────────────────────────────────────


@cli.command()
@click.option("--api-key", type=str, default=None, help="Medusa dashboard API key.")
@click.option("--dashboard-url", type=str, default=None, help="Dashboard API URL.")
@click.option(
    "--claude-api-key", type=str, default=None, help="Anthropic API key for AI scans."
)
@click.option(
    "--ai-mode",
    type=click.Choice(["byok", "proxied"]),
    default=None,
    help="AI mode: bring your own key or use dashboard proxy.",
)
@click.pass_context
def configure(
    ctx: click.Context,
    api_key: str | None,
    dashboard_url: str | None,
    claude_api_key: str | None,
    ai_mode: str | None,
) -> None:
    """Set up Medusa CLI configuration.

    Saves settings to ~/.medusa/config.yaml. Run without flags for an
    interactive setup wizard, or pass flags to set individual values.

    \b
    Examples:
      medusa configure
      medusa configure --api-key sk_medusa_abc123
      medusa configure --claude-api-key sk-ant-... --ai-mode byok
    """
    from medusa.cli.config import (
        CONFIG_FILE,
        load_user_config,
        save_user_config,
    )

    quiet = ctx.obj.get("quiet", False)
    config = load_user_config()

    # Interactive prompts if no flags provided
    no_flags = all(
        v is None for v in [api_key, dashboard_url, claude_api_key, ai_mode]
    )
    if no_flags:
        if not quiet:
            console.print(
                "  [bold]Dashboard Settings[/bold]",
            )
            console.print(
                "  [dim]Connect to your Medusa dashboard for scan history, "
                "reports, and credits.[/dim]"
            )
            console.print()

        api_key = click.prompt(
            "  Medusa API key",
            default=config.api_key or "",
            show_default=bool(config.api_key),
        )
        dashboard_url = click.prompt(
            "  Dashboard URL",
            default=config.dashboard_url,
        )

        if not quiet:
            console.print()
            console.print(
                "  [bold]AI Analysis Settings[/bold]",
            )
            console.print(
                "  [dim]Enable AI-powered security analysis using Claude. "
                "Uses 1 credit per server scanned.[/dim]"
            )
            console.print()

        claude_api_key = click.prompt(
            "  Anthropic API key (leave blank to skip)",
            default=config.claude_api_key or "",
            show_default=bool(config.claude_api_key),
        )
        ai_mode = click.prompt(
            "  AI mode",
            type=click.Choice(["byok", "proxied"]),
            default=config.ai_mode,
        )

    if api_key is not None:
        config.api_key = api_key
    if dashboard_url is not None:
        config.dashboard_url = dashboard_url
    if claude_api_key is not None:
        config.claude_api_key = claude_api_key or None
    if ai_mode is not None:
        config.ai_mode = ai_mode

    save_user_config(config)

    if not quiet:
        console.print()
        console.print(
            f"  [green]▸ Configuration saved to {CONFIG_FILE}[/green]"
        )
        console.print()


# ── settings ──────────────────────────────────────────────────────────────


@cli.command()
@click.pass_context
def settings(ctx: click.Context) -> None:
    """Display current Medusa CLI configuration.

    Shows all configured values including API keys (masked),
    dashboard URL, and AI analysis settings.
    """
    from medusa.cli.config import CONFIG_FILE, load_user_config

    quiet = ctx.obj.get("quiet", False)
    config = load_user_config()

    if not quiet:
        console.print(f"  [dim]Config: {CONFIG_FILE}[/dim]")
        console.print()

    # ── Dashboard section
    dash_table = Table(
        show_header=False, box=None, padding=(0, 2), pad_edge=False
    )
    dash_table.add_column("Key", style="bold", width=20)
    dash_table.add_column("Value")

    if config.api_key:
        masked = _mask_key(config.api_key)
        dash_table.add_row("API Key", f"[green]{masked}[/green]")
    else:
        dash_table.add_row("API Key", "[red]Not configured[/red]")

    dash_table.add_row("Dashboard URL", f"[dim]{config.dashboard_url}[/dim]")

    console.print(
        Panel(
            dash_table,
            title="[bold]Dashboard[/bold]",
            border_style="bright_blue",
            padding=(1, 2),
        )
    )

    # ── AI section
    ai_table = Table(
        show_header=False, box=None, padding=(0, 2), pad_edge=False
    )
    ai_table.add_column("Key", style="bold", width=20)
    ai_table.add_column("Value")

    if config.claude_api_key:
        masked = _mask_key(config.claude_api_key)
        ai_table.add_row("Anthropic API Key", f"[green]{masked}[/green]")
    else:
        ai_table.add_row("Anthropic API Key", "[dim]Not configured[/dim]")

    mode_display = (
        "[cyan]BYOK[/cyan] — using your own Claude key"
        if config.ai_mode == "byok"
        else "[cyan]Proxied[/cyan] — routed through dashboard"
    )
    ai_table.add_row("AI Mode", mode_display)
    ai_table.add_row("Claude Model", f"[dim]{config.claude_model}[/dim]")

    console.print(
        Panel(
            ai_table,
            title="[bold]AI Analysis[/bold]",
            border_style="bright_magenta",
            padding=(1, 2),
        )
    )
    console.print()


# ── Helpers ───────────────────────────────────────────────────────────────


def _mask_key(key: str) -> str:
    """Mask a key: show first 12 chars + '...'."""
    if len(key) > 12:
        return key[:12] + "..."
    return key


if __name__ == "__main__":
    cli()
