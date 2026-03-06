"""Medusa CLI entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

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
from medusa.connectors.config_discovery import (
    CLIENT_DISPLAY_NAMES,
    CONFIG_PATHS,
    discover_servers,
    discover_servers_detailed,
)
from medusa.connectors.http import HttpConnector
from medusa.connectors.stdio import StdioConnector
from medusa.core.models import Status
from medusa.core.registry import CheckRegistry
from medusa.core.scanner import ScanEngine, has_findings_above_threshold
from medusa.reporters.console_reporter import ConsoleReporter
from medusa.reporters.html_reporter import HtmlReporter
from medusa.reporters.json_reporter import JsonReporter
from medusa.reporters.markdown_reporter import MarkdownReporter
from medusa.reporters.sarif_reporter import SarifReporter
from medusa.utils.config_parser import load_config

if TYPE_CHECKING:
    from medusa.gateway.policy import GatewayPolicy

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
  medusa quickscan                                    Discover & scan everything
  medusa scan --http http://localhost:3000/mcp        Scan specific server
  medusa scan --deep                                  Static + AI deep analysis
  medusa scan -o html --output-file report.html       HTML dashboard
  medusa scan -o json --fail-on high                  CI/CD integration
  medusa scan --generate-baseline .medusa-baseline.json   Save baseline
  medusa scan --baseline .medusa-baseline.json        Show only new findings
  medusa diff before.json after.json                  Compare two scans
  medusa baseline show .medusa-baseline.json          View baseline
  medusa list-checks                                  Browse all checks
  medusa configure                                    Setup wizard

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
    using 559 checks across 26 categories, with an optional AI reasoning
    engine for finding validation, attack chain correlation, and gap
    discovery.
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
    help="Static checks only (default).",
)
@click.option(
    "--deep",
    "flag_deep",
    is_flag=True,
    default=False,
    help="Static + AI deep analysis: validates findings, detects attack chains, discovers gaps.",
)
@click.option("--ai", "flag_ai", is_flag=True, default=False, hidden=True)
@click.option("--all", "flag_all", is_flag=True, default=False, hidden=True)
@click.option("--reason", "flag_reason", is_flag=True, default=False, hidden=True)
@click.option(
    "--claude-api-key",
    type=str,
    default=None,
    help="Anthropic API key (overrides ANTHROPIC_API_KEY env var).",
)
@click.option(
    "--ai-mode",
    type=click.Choice(["byok", "proxied"]),
    default=None,
    help="AI key mode: bring-your-own-key or dashboard proxy.",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=str,
    default=None,
    help="Path to baseline file. Only show NEW findings not in the baseline.",
)
@click.option(
    "--generate-baseline",
    "generate_baseline_path",
    type=str,
    default=None,
    help="Generate a baseline file from scan results.",
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
    flag_deep: bool,
    flag_ai: bool,
    flag_all: bool,
    flag_reason: bool,
    claude_api_key: str | None,
    ai_mode: str | None,
    baseline_path: str | None,
    generate_baseline_path: str | None,
) -> None:
    """Scan MCP servers for security vulnerabilities.

    Run 462+ security checks across 25 categories against your MCP servers.
    Use --deep to enable AI deep analysis that validates findings,
    detects attack chains, identifies false positives, and discovers gaps.

    \b
    Scan modes:
      (default)  Static checks only — fast, free
      --deep     Static + AI deep analysis (recommended)

    \b
    Output formats:
      -o console   Rich terminal tables with scoring (default)
      -o json      Machine-readable JSON
      -o html      Interactive HTML dashboard
      -o markdown  Markdown report
      -o sarif     SARIF for GitHub/IDE integration

    \b
    Examples:
      medusa scan                                     Auto-discover & scan
      medusa scan --http http://localhost:3000/mcp     Scan specific server
      medusa scan --deep                               Static + AI deep analysis
      medusa scan -o html --output-file report.html    HTML dashboard
      medusa scan -o json --fail-on high               CI/CD gate
      medusa scan --compliance owasp_mcp_top10         OWASP compliance
    """
    quiet = ctx.obj.get("quiet", False)

    # ── Resolve scan mode ─────────────────────────────────────────
    # Deprecated flags map to --deep (static + reasoning engine)
    if flag_ai and not quiet:
        console.print("  [yellow]--ai is deprecated. Use --deep instead.[/yellow]")
    if flag_all and not quiet:
        console.print("  [yellow]--all is deprecated. Use --deep instead.[/yellow]")
    if flag_reason and not quiet:
        console.print("  [yellow]--reason is deprecated. Use --deep instead.[/yellow]")

    scan_mode = "static"
    enable_reasoning = flag_deep or flag_reason or flag_ai or flag_all

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
            f"  [green]▸ Found {len(connectors)} {server_word}:[/green] [dim]{names}[/dim]"
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
    if enable_reasoning:
        _setup_ai_scan(ctx, ai_mode, claude_api_key, api_key, quiet)
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
        enable_reasoning=enable_reasoning,
    )

    num_checks = len(engine.checks)
    # Add 1 work unit per server for reasoning step
    reasoning_extra = len(connectors) if enable_reasoning else 0
    total_work = len(connectors) * num_checks + reasoning_extra

    if not quiet:
        check_word = "check" if num_checks == 1 else "checks"
        deep_label = " + AI deep analysis" if enable_reasoning else ""
        console.print(
            f"  [green]▸ Running {num_checks} {check_word}[/green] [dim](static{deep_label})[/dim]"
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
                if detail == "ai_reasoning":
                    progress.update(
                        task,
                        advance=1,
                        description="Analyzing findings...",
                    )
                else:
                    progress.update(task, advance=1)
            elif event == "server_start":
                progress.update(
                    task,
                    description=(f"Scanning [cyan]{detail}[/cyan]..."),
                )

        engine.progress_callback = on_progress
        result = asyncio.run(engine.scan())

    # ── Baseline handling ────────────────────────────────────────
    if generate_baseline_path:
        from medusa.core.baseline import generate_baseline, save_baseline

        baseline = generate_baseline(result)
        save_baseline(baseline, generate_baseline_path)
        if not quiet:
            console.print(
                f"  [green]▸ Baseline saved:[/green] "
                f"{generate_baseline_path} "
                f"[dim]({len(baseline.entries)} findings)[/dim]"
            )

    baseline_stats: dict[str, int] | None = None
    if baseline_path:
        from medusa.core.baseline import (
            filter_new_findings,
            load_baseline,
        )

        try:
            baseline = load_baseline(baseline_path)
            new_findings, baselined_findings, resolved_fps = filter_new_findings(result, baseline)
            baseline_stats = {
                "new": sum(1 for f in new_findings if f.status == Status.FAIL),
                "baselined": len(baselined_findings),
                "resolved": len(resolved_fps),
            }

            # Replace findings in result with only new findings
            result = result.model_copy(update={"findings": new_findings})

            if not quiet:
                console.print(
                    f"  [green]▸ Baseline:[/green] "
                    f"[cyan]{baseline_stats['new']}[/cyan] new, "
                    f"[dim]{baseline_stats['baselined']} baselined, "
                    f"{baseline_stats['resolved']} resolved[/dim]"
                )
        except FileNotFoundError:
            if not quiet:
                console.print(f"  [yellow]⚠ Baseline not found: {baseline_path}[/yellow]")
        except ValueError as e:
            if not quiet:
                console.print(f"  [yellow]⚠ Invalid baseline: {e}[/yellow]")

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
                    f"[yellow]⚠ Compliance framework not found: {compliance_name}[/yellow]"
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


# ── quickscan ─────────────────────────────────────────────────────────────


@cli.command()
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
    "--severity",
    type=str,
    default=None,
    help="Minimum severity to include in results.",
)
@click.option(
    "--fail-on",
    type=str,
    default="critical",
    help="Exit code 1 if findings at or above this severity.  [default: critical]",
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
    "--max-concurrency",
    type=int,
    default=4,
    help="Max parallel server scans.  [default: 4]",
)
@click.pass_context
def quickscan(
    ctx: click.Context,
    output_format: str,
    output_file: str | None,
    severity: str | None,
    fail_on: str,
    upload: bool,
    api_key: str | None,
    max_concurrency: int,
) -> None:
    """Auto-discover and scan ALL MCP servers on your machine.

    Finds servers from Claude Desktop, Cursor, VS Code, Windsurf,
    Claude Code, Gemini CLI, Zed, Cline, Roo Code, Continue.dev,
    Amazon Q, and GitHub Copilot configs — no setup needed.

    \b
    Examples:
      medusa quickscan
      medusa quickscan --severity high
      medusa quickscan -o html --output-file report.html
      medusa quickscan -o json --fail-on high
    """
    quiet = ctx.obj.get("quiet", False)

    if not quiet:
        console.print()
        console.print("  [bold green]🔍 Medusa Quick Scan[/bold green]")
        console.print()

    # Discover all servers grouped by client
    grouped = discover_servers_detailed(include_project_configs=True)

    if not grouped:
        if not quiet:
            # Build list of checked locations
            from medusa.connectors.config_discovery import _get_platform_key

            platform_key = _get_platform_key()
            lines = ["[yellow]No MCP servers found.[/yellow]\n"]
            lines.append("Checked these locations:")
            for client_key, paths in CONFIG_PATHS.items():
                display = CLIENT_DISPLAY_NAMES.get(client_key, client_key)
                path_str = paths.get(platform_key, "")
                lines.append(f"  [red]✗[/red] {display} [dim]({path_str})[/dim]")
            lines.append("")
            lines.append("To scan a specific server:")
            lines.append("  [cyan]medusa scan --stdio[/cyan] 'npx my-server'")
            lines.append("  [cyan]medusa scan --http[/cyan] http://localhost:3000/mcp")
            console.print(
                Panel(
                    "\n".join(lines),
                    title="[bold yellow]No Targets[/bold yellow]",
                    border_style="yellow",
                    padding=(1, 2),
                )
            )
        sys.exit(3)

    # Flatten connectors and display discovery summary
    connectors = []
    total_servers = 0
    for client_name, client_connectors in grouped.items():
        connectors.extend(client_connectors)
        total_servers += len(client_connectors)

    if not quiet:
        client_word = "client" if len(grouped) == 1 else "clients"
        server_word = "server" if total_servers == 1 else "servers"
        console.print(
            f"  [green]Discovered {total_servers} MCP "
            f"{server_word} across "
            f"{len(grouped)} {client_word}:[/green]"
        )
        console.print()

        for client_name, client_connectors in grouped.items():
            console.print(f"  [bold]{client_name}:[/bold]")
            for c in client_connectors:
                transport = "http" if hasattr(c, "url") else "stdio"
                console.print(f"    [dim]•[/dim] {c.name} [dim]({transport})[/dim]")
        console.print()

    # Discover and filter checks
    registry = CheckRegistry()
    registry.discover_checks()

    severities = [severity] if severity else None

    engine = ScanEngine(
        connectors=connectors,
        registry=registry,
        severities=severities,
        max_concurrency=max_concurrency,
        scan_mode="static",
        enable_reasoning=False,
    )

    num_checks = len(engine.checks)
    total_work = len(connectors) * num_checks

    if not quiet:
        check_word = "check" if num_checks == 1 else "checks"
        console.print(f"  [green]▸ Running {num_checks} {check_word}[/green] [dim](static)[/dim]")
        console.print()

    # Run scan with progress bar
    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(
            bar_width=40,
            complete_style="green",
            finished_style="bold green",
        ),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        disable=quiet,
    ) as progress:
        task = progress.add_task("Scanning...", total=total_work)

        failed_servers: list[str] = []

        def on_progress(event: str, detail: str) -> None:
            if event == "check_done":
                progress.update(task, advance=1)
            elif event == "server_start":
                progress.update(
                    task,
                    description=f"Scanning [cyan]{detail}[/cyan]...",
                )
            elif event == "server_done":
                pass  # tracked via result.servers_scanned below

        engine.progress_callback = on_progress
        result = asyncio.run(engine.scan())

    # Report connection failures
    failed_count = total_servers - result.servers_scanned
    if failed_count > 0 and not quiet:
        # Identify which servers failed by checking scores
        scanned_names = {s.server_name for s in result.server_scores}
        all_names = [c.name for c in connectors]
        failed_servers = [n for n in all_names if n not in scanned_names]
        console.print()
        console.print(f"  [yellow]⚠ {failed_count} server(s) failed to connect (skipped):[/yellow]")
        for name in failed_servers:
            console.print(f"    [dim]•[/dim] [yellow]{name}[/yellow]")
        console.print()

    # Generate report
    reporters = {
        "console": ConsoleReporter,
        "json": JsonReporter,
        "html": HtmlReporter,
        "markdown": MarkdownReporter,
        "sarif": SarifReporter,
    }

    effective_format = output_format
    if output_format == "console" and not sys.stdout.isatty() and not output_file:
        effective_format = "json"

    reporter = reporters[effective_format]()

    if output_file:
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

    # Print summary for non-console formats
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
    medusa_key = api_key or os.environ.get("MEDUSA_API_KEY", "") or (user_config.api_key or "")

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
            supabase_url=user_config.supabase_url,
        )

    # Set up credit manager (needs Medusa API key)
    credit_mgr = None
    if medusa_key:
        credit_mgr = CreditManager(
            api_key=medusa_key,
            supabase_url=user_config.supabase_url,
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
        logger.warning("Credit deduction failed: %s — continuing anyway", e)
        return True


# ── Upload ────────────────────────────────────────────────────────────────


def _upload_results(result, api_key: str | None, quiet: bool) -> None:
    """Upload scan results to the Medusa dashboard via Supabase Edge Function."""
    from medusa.cli.config import load_user_config

    user_config = load_user_config()
    base = user_config.supabase_url.rstrip("/")
    upload_url = f"{base}/functions/v1/reports"

    # Resolve API key: --api-key flag > env var > saved config
    resolved_key = api_key or os.environ.get("MEDUSA_API_KEY", "") or (user_config.api_key or "")

    if not resolved_key:
        console.print()
        console.print(
            Panel(
                "[red]API key required for upload.[/red]\n\n"
                "Provide one of:\n"
                "  [cyan]--api-key[/cyan] med_...\n"
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
        if resp.status_code in (200, 201):
            if not quiet:
                data = resp.json()
                scan_id = data.get("scan_id", "")
                dash = user_config.dashboard_url.rstrip("/")
                console.print(
                    f"  [green]▸ Uploaded to dashboard:[/green] [dim]{dash}/reports/{scan_id}[/dim]"
                )
        else:
            try:
                detail = resp.json().get("error", resp.text)
            except (ValueError, KeyError):
                detail = resp.text[:200] or f"HTTP {resp.status_code}"
            console.print(f"  [red]✗ Upload failed ({resp.status_code}):[/red] {detail}")
    except httpx.HTTPError as exc:
        console.print(f"  [red]✗ Upload failed:[/red] {exc}")


# ── Benchmark Upload ─────────────────────────────────────────────────────


def _upload_benchmark(report, api_key: str | None, quiet: bool) -> None:
    """Upload benchmark results to the Medusa dashboard."""
    from medusa.cli.config import load_user_config

    user_config = load_user_config()

    # Build Edge Function URL from Supabase project base
    base = user_config.supabase_url.rstrip("/")
    upload_url = f"{base}/functions/v1/upload-benchmark"

    # Resolve API key: flag > env var > saved config
    resolved_key = api_key or os.environ.get("MEDUSA_API_KEY", "") or (user_config.api_key or "")

    if not resolved_key:
        console.print()
        console.print(
            Panel(
                "[red]API key required for upload.[/red]\n\n"
                "Provide one of:\n"
                "  [cyan]--api-key[/cyan] sk-med_...\n"
                "  [cyan]MEDUSA_API_KEY[/cyan] environment variable\n"
                "  [cyan]medusa configure[/cyan] to save it",
                title="[bold red]Benchmark Upload Failed[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        return

    if not quiet:
        console.print("\n  [dim]Uploading benchmark to dashboard...[/dim]")

    try:
        resp = httpx.post(
            upload_url,
            json=report.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {resolved_key}"},
            timeout=30,
        )
        if resp.status_code == 200:
            body = resp.json()
            run_id = body.get("id", "")
            server_count = body.get("servers", 0)
            if not quiet:
                console.print(
                    f"  [green]▸ Benchmark uploaded:[/green] "
                    f"[dim]{run_id} ({server_count} servers)[/dim]"
                )
        else:
            try:
                detail = resp.json().get("error", resp.text)
            except (ValueError, KeyError):
                detail = resp.text[:200] or f"HTTP {resp.status_code}"
            console.print(f"  [red]✗ Upload failed ({resp.status_code}):[/red] {detail}")
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

    title = f"Medusa Security Checks — {len(all_checks)} checks"

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
        "info": "dim",
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


# ── list-advisories ──────────────────────────────────────────────────────


@cli.command("list-advisories")
@click.option("--severity", type=str, default=None, help="Filter by severity.")
@click.option("--check", type=str, default=None, help="Show advisories for a specific check ID.")
@click.option("--tag", type=str, default=None, help="Filter by tag.")
def list_advisories_cmd(severity: str | None, check: str | None, tag: str | None) -> None:
    """Browse the Medusa Advisory Database (MAD).

    Displays known MCP attack patterns with severity ratings, affected
    tool patterns, related checks, and OWASP MCP Top 10 mappings.
    """
    from medusa.advisories.loader import (
        get_advisories_by_severity,
        get_advisories_by_tag,
        get_advisories_for_check,
        load_all_advisories,
    )

    if check:
        advisories = get_advisories_for_check(check)
    elif severity:
        advisories = get_advisories_by_severity(severity)
    elif tag:
        advisories = get_advisories_by_tag(tag)
    else:
        advisories = list(load_all_advisories())

    if not advisories:
        console.print("[dim]No advisories found matching the filter.[/dim]")
        return

    table = Table(title=f"Medusa Advisory Database ({len(advisories)} advisories)")
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title", max_width=60)
    table.add_column("Checks", style="dim")
    table.add_column("OWASP", style="dim")

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }

    for adv in advisories:
        sev_style = severity_styles.get(adv.severity, "white")
        table.add_row(
            adv.id,
            f"[{sev_style}]{adv.severity.upper()}[/{sev_style}]",
            adv.title,
            ", ".join(adv.related_checks[:5]),
            ", ".join(adv.owasp_mcp[:3]),
        )

    console.print(table)


# ── benchmark ─────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--servers",
    "-s",
    type=str,
    default=None,
    help="Comma-separated server names to benchmark (default: all).",
)
@click.option(
    "--output-dir",
    type=str,
    default="benchmarks/results",
    help="Directory to save benchmark results.",
)
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=60,
    help="Connection timeout per server in seconds.  [default: 60]",
)
@click.option(
    "--markdown",
    is_flag=True,
    default=False,
    help="Output markdown report to stdout.",
)
@click.option(
    "--upload",
    is_flag=True,
    default=False,
    help="Upload benchmark results to your Medusa dashboard.",
)
@click.option(
    "--api-key",
    type=str,
    default=None,
    help="Medusa API key for upload.",
)
@click.pass_context
def benchmark(
    ctx: click.Context,
    servers: str | None,
    output_dir: str,
    timeout: int,
    markdown: bool,
    upload: bool,
    api_key: str | None,
) -> None:
    """Run benchmarks against popular MCP servers.

    Scans a catalog of well-known MCP servers and generates a
    "State of MCP Security" report with scores and grades.
    Servers requiring missing environment variables are skipped.

    \b
    Examples:
      medusa benchmark                                   Scan all catalog servers
      medusa benchmark --servers filesystem,memory       Scan specific servers
      medusa benchmark --markdown                        Markdown report to stdout
      medusa benchmark --upload                          Upload results to dashboard
      medusa benchmark --timeout 120 --output-dir ./out  Custom timeout & output
    """
    from medusa.benchmarks.report import (
        generate_markdown_report,
        print_benchmark_report,
        save_benchmark_results,
    )
    from medusa.benchmarks.runner import run_benchmark

    quiet = ctx.obj.get("quiet", False)
    server_list = [s.strip() for s in servers.split(",")] if servers else None

    if not quiet:
        console.print()
        if server_list:
            console.print(
                f"  [green]\u25b8 Benchmarking:[/green] [dim]{', '.join(server_list)}[/dim]"
            )
        else:
            console.print("  [green]\u25b8 Benchmarking all catalog servers[/green]")
        console.print()

    report = asyncio.run(run_benchmark(server_names=server_list, timeout=timeout))

    if markdown:
        console.print(generate_markdown_report(report))
    else:
        print_benchmark_report(report, console=console)

    # Save results
    filepath = save_benchmark_results(report, output_dir=output_dir)
    if not quiet:
        console.print(f"\n  [dim]Results saved to {filepath}[/dim]")

    # Upload to dashboard
    if upload:
        _upload_benchmark(report, api_key=api_key, quiet=quiet)


# ── configure ─────────────────────────────────────────────────────────────


@cli.command()
@click.option("--api-key", type=str, default=None, help="Medusa dashboard API key.")
@click.option("--dashboard-url", type=str, default=None, help="Dashboard API URL.")
@click.option(
    "--supabase-url",
    type=str,
    default=None,
    help="Supabase project URL.",
)
@click.option("--claude-api-key", type=str, default=None, help="Anthropic API key for AI scans.")
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
    supabase_url: str | None,
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
        v is None for v in [api_key, dashboard_url, supabase_url, claude_api_key, ai_mode]
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
    if supabase_url is not None:
        config.supabase_url = supabase_url
    if claude_api_key is not None:
        config.claude_api_key = claude_api_key or None
    if ai_mode is not None:
        config.ai_mode = ai_mode

    save_user_config(config)

    if not quiet:
        console.print()
        console.print(f"  [green]▸ Configuration saved to {CONFIG_FILE}[/green]")
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
    dash_table = Table(show_header=False, box=None, padding=(0, 2), pad_edge=False)
    dash_table.add_column("Key", style="bold", width=20)
    dash_table.add_column("Value")

    if config.api_key:
        masked = _mask_key(config.api_key)
        dash_table.add_row("API Key", f"[green]{masked}[/green]")
    else:
        dash_table.add_row("API Key", "[red]Not configured[/red]")

    dash_table.add_row("Dashboard URL", f"[dim]{config.dashboard_url}[/dim]")
    dash_table.add_row("Supabase URL", f"[dim]{config.supabase_url}[/dim]")

    console.print(
        Panel(
            dash_table,
            title="[bold]Dashboard[/bold]",
            border_style="bright_blue",
            padding=(1, 2),
        )
    )

    # ── AI section
    ai_table = Table(show_header=False, box=None, padding=(0, 2), pad_edge=False)
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


# ── diff ─────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("before_file", type=click.Path(exists=True))
@click.argument("after_file", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    "output_format",
    type=click.Choice(["console", "json"]),
    default="console",
    help="Output format.  [default: console]",
)
@click.option(
    "--output-file",
    type=str,
    default=None,
    help="Write diff to file instead of stdout.",
)
@click.option(
    "--fail-on-new",
    is_flag=True,
    default=False,
    help="Exit code 1 if new findings are detected.",
)
@click.pass_context
def diff(
    ctx: click.Context,
    before_file: str,
    after_file: str,
    output_format: str,
    output_file: str | None,
    fail_on_new: bool,
) -> None:
    """Compare two scan results and show changes.

    Compares BEFORE_FILE and AFTER_FILE (JSON scan results) to show
    new findings, resolved findings, severity changes, and score changes.

    Perfect for CI/CD: "did this change introduce new security issues?"

    \b
    Examples:
      medusa diff scan-before.json scan-after.json
      medusa diff baseline.json latest.json --fail-on-new
      medusa diff old.json new.json -o json --output-file changes.json
    """
    from medusa.core.diff import diff_scan_results
    from medusa.core.models import ScanResult

    quiet = ctx.obj.get("quiet", False)

    try:
        before = ScanResult.model_validate_json(Path(before_file).read_text())
        after = ScanResult.model_validate_json(Path(after_file).read_text())
    except Exception as e:
        console.print(f"  [red]Failed to parse scan results: {e}[/red]")
        sys.exit(2)

    scan_diff = diff_scan_results(before, after)

    if output_format == "json":
        content = scan_diff.model_dump_json(indent=2)
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            Path(output_file).write_text(content)
            if not quiet:
                console.print(f"  [green]▸ Diff saved:[/green] {output_file}")
        else:
            click.echo(content)
    else:
        _print_diff(scan_diff, quiet)

    if fail_on_new and scan_diff.total_new > 0:
        sys.exit(1)


def _print_diff(scan_diff, quiet: bool) -> None:
    """Pretty-print a ScanDiff to the console."""
    from medusa.core.diff import ScanDiff

    d: ScanDiff = scan_diff

    # Score change header
    score_delta = d.aggregate_score_after - d.aggregate_score_before
    if score_delta > 0:
        delta_str = f"[green]+{score_delta:.1f}[/green]"
    elif score_delta < 0:
        delta_str = f"[red]{score_delta:.1f}[/red]"
    else:
        delta_str = "[dim]+0.0[/dim]"

    console.print()
    console.print(
        Panel(
            f"[bold]Score:[/bold] {d.aggregate_score_before}/10 "
            f"({d.aggregate_grade_before}) → "
            f"{d.aggregate_score_after}/10 "
            f"({d.aggregate_grade_after})  "
            f"[{delta_str}]\n\n"
            f"[cyan]{d.total_new}[/cyan] new findings  |  "
            f"[green]{d.total_resolved}[/green] resolved  |  "
            f"[yellow]{d.total_severity_changes}[/yellow] severity changes",
            title="[bold]Scan Diff[/bold]",
            border_style="bright_blue",
            padding=(1, 2),
        )
    )

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    # New findings
    if d.new_findings:
        console.print()
        console.print("  [bold red]New Findings[/bold red]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Check ID", style="cyan", width=10)
        table.add_column("Title")
        table.add_column("Server")
        table.add_column("Resource")

        for f in d.new_findings:
            sev_style = severity_styles.get(f.severity, "")
            table.add_row(
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                f.check_id,
                f.check_title,
                f.server_name,
                f.resource_name,
            )
        console.print(table)

    # Resolved findings
    if d.resolved_findings:
        console.print()
        console.print("  [bold green]Resolved Findings[/bold green]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Check ID", style="cyan", width=10)
        table.add_column("Title")
        table.add_column("Server")

        for f in d.resolved_findings:
            sev_style = severity_styles.get(f.severity, "")
            table.add_row(
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                f.check_id,
                f.check_title,
                f.server_name,
            )
        console.print(table)

    # Severity changes
    if d.severity_changes:
        console.print()
        console.print("  [bold yellow]Severity Changes[/bold yellow]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Check ID", style="cyan", width=10)
        table.add_column("Server")
        table.add_column("Old Severity")
        table.add_column("New Severity")

        for c in d.severity_changes:
            old_style = severity_styles.get(c.old_severity, "")
            new_style = severity_styles.get(c.new_severity, "")
            table.add_row(
                c.check_id,
                c.server_name,
                f"[{old_style}]{c.old_severity}[/{old_style}]",
                f"[{new_style}]{c.new_severity}[/{new_style}]",
            )
        console.print(table)

    # Server score changes
    if d.server_score_changes:
        console.print()
        console.print("  [bold]Server Score Changes[/bold]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Server")
        table.add_column("Before")
        table.add_column("After")
        table.add_column("Delta")

        for s in d.server_score_changes:
            if s.score_delta > 0:
                delta = f"[green]+{s.score_delta:.1f}[/green]"
            elif s.score_delta < 0:
                delta = f"[red]{s.score_delta:.1f}[/red]"
            else:
                delta = "[dim]+0.0[/dim]"
            table.add_row(
                s.server_name,
                f"{s.old_score}/10 ({s.old_grade})",
                f"{s.new_score}/10 ({s.new_grade})",
                delta,
            )
        console.print(table)

    console.print()


# ── baseline ─────────────────────────────────────────────────────────────


@cli.group("baseline")
def baseline_group() -> None:
    """Manage scan baselines for suppression and tracking.

    \b
    Commands:
      show       Display baseline contents
      suppress   Suppress a finding by fingerprint
      unsuppress Remove suppression from a finding
    """


@baseline_group.command("show")
@click.argument("baseline_file", type=click.Path(exists=True))
@click.option(
    "--suppressed-only",
    is_flag=True,
    default=False,
    help="Show only suppressed findings.",
)
@click.pass_context
def baseline_show(
    ctx: click.Context,
    baseline_file: str,
    suppressed_only: bool,
) -> None:
    """Display contents of a baseline file."""
    from medusa.core.baseline import load_baseline

    try:
        baseline = load_baseline(baseline_file)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"  [red]{e}[/red]")
        sys.exit(2)

    entries = baseline.entries
    if suppressed_only:
        entries = [e for e in entries if e.suppressed]

    console.print()
    console.print(
        f"  [bold]Baseline:[/bold] {baseline_file}  "
        f"[dim]({len(baseline.entries)} findings, "
        f"{sum(1 for e in baseline.entries if e.suppressed)} suppressed)[/dim]"
    )
    console.print(f"  [dim]Created: {baseline.created_at}  |  Scan: {baseline.scan_id}[/dim]")
    console.print()

    if not entries:
        console.print("  [dim]No findings to show.[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Fingerprint", style="cyan", width=18)
    table.add_column("Check ID", width=10)
    table.add_column("Server")
    table.add_column("Resource")
    table.add_column("Severity", width=10)
    table.add_column("Suppressed")

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for entry in entries:
        sev_style = severity_styles.get(entry.severity, "")
        if entry.suppressed:
            sup_text = f"[dim]{entry.suppression_reason or 'yes'}[/dim]"
        else:
            sup_text = "-"
        table.add_row(
            entry.fingerprint,
            entry.check_id,
            entry.server_name,
            entry.resource_name,
            f"[{sev_style}]{entry.severity}[/{sev_style}]",
            sup_text,
        )

    console.print(table)
    console.print()


@baseline_group.command("suppress")
@click.argument("baseline_file", type=click.Path(exists=True))
@click.argument("fingerprint")
@click.option(
    "--reason",
    type=str,
    required=True,
    help='Reason for suppression (e.g. "accepted risk per JIRA-1234").',
)
def baseline_suppress(
    baseline_file: str,
    fingerprint: str,
    reason: str,
) -> None:
    """Suppress a finding in a baseline by its fingerprint.

    \b
    Examples:
      medusa baseline suppress .medusa-baseline.json a1b2c3d4 --reason "accepted risk"
    """
    from medusa.core.baseline import (
        load_baseline,
        save_baseline,
        suppress_finding,
    )

    try:
        baseline = load_baseline(baseline_file)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"  [red]{e}[/red]")
        sys.exit(2)

    if suppress_finding(baseline, fingerprint, reason):
        save_baseline(baseline, baseline_file)
        console.print(
            f'  [green]▸ Suppressed:[/green] {fingerprint}  [dim]reason: "{reason}"[/dim]'
        )
    else:
        console.print(f"  [yellow]Fingerprint not found in baseline: {fingerprint}[/yellow]")
        sys.exit(2)


@baseline_group.command("unsuppress")
@click.argument("baseline_file", type=click.Path(exists=True))
@click.argument("fingerprint")
def baseline_unsuppress(
    baseline_file: str,
    fingerprint: str,
) -> None:
    """Remove suppression from a finding.

    \b
    Examples:
      medusa baseline unsuppress .medusa-baseline.json a1b2c3d4
    """
    from medusa.core.baseline import (
        load_baseline,
        save_baseline,
        unsuppress_finding,
    )

    try:
        baseline = load_baseline(baseline_file)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"  [red]{e}[/red]")
        sys.exit(2)

    if unsuppress_finding(baseline, fingerprint):
        save_baseline(baseline, baseline_file)
        console.print(f"  [green]▸ Unsuppressed:[/green] {fingerprint}")
    else:
        console.print(f"  [yellow]Fingerprint not found in baseline: {fingerprint}[/yellow]")
        sys.exit(2)


# ── watch ────────────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--interval",
    type=int,
    default=300,
    help="Seconds between scans.  [default: 300]",
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
@click.pass_context
def watch(
    ctx: click.Context,
    interval: int,
    config_file: str | None,
    scan_config: str | None,
) -> None:
    """Continuously monitor MCP servers for configuration changes.

    Runs scans at a configurable interval and reports when tool definitions
    change (added, removed, or modified tools). Useful for detecting
    supply-chain drift and unauthorized modifications.

    \b
    Examples:
      medusa watch                         Monitor every 5 minutes
      medusa watch --interval 60           Monitor every minute
      medusa watch --config-file mcp.json  Watch specific config
    """
    import signal
    import time as _time

    quiet = ctx.obj.get("quiet", False)

    if not quiet:
        console.print()
        console.print(
            f"  [green]\u25b8 Watching MCP servers[/green] "
            f"[dim](every {interval}s, Ctrl+C to stop)[/dim]"
        )
        console.print()

    # Handle graceful shutdown
    stop = False

    def _handle_signal(signum, frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    scan_count = 0
    while not stop:
        scan_count += 1

        # Build connectors
        extra_configs = [config_file] if config_file else []
        config = load_config(scan_config)
        extra_configs.extend(config.discovery.config_files)
        connectors = discover_servers(additional_config_files=extra_configs or None)

        if not connectors:
            if not quiet:
                console.print("  [yellow]No servers found. Retrying...[/yellow]")
            _time.sleep(interval)
            continue

        # Run scan
        registry = CheckRegistry()
        registry.discover_checks()

        engine = ScanEngine(
            connectors=connectors,
            registry=registry,
            scan_mode="static",
        )

        result = asyncio.run(engine.scan())

        # Report changes if any
        if result.changes:
            total = sum(len(c) for c in result.changes.values())
            if not quiet:
                console.print(
                    f"  [bold yellow]\u25b8 Scan #{scan_count}:[/bold yellow] "
                    f"[yellow]{total} change(s) detected[/yellow]"
                )
                for server, changes in result.changes.items():
                    for change in changes:
                        console.print(
                            f"    {change['type']}: {change['name']} [dim]({server})[/dim]"
                        )
                console.print()
        elif not quiet and scan_count == 1:
            console.print(
                f"  [dim]Scan #{scan_count}: No previous scan \u2014 baseline recorded.[/dim]"
            )
        elif not quiet:
            console.print(f"  [dim]Scan #{scan_count}: No changes detected.[/dim]")

        # Wait for next interval
        _time.sleep(interval)

    if not quiet:
        console.print("\n  [dim]Watch stopped.[/dim]")


# ── gateway ──────────────────────────────────────────────────────────────


@cli.group("gateway")
def gateway_group() -> None:
    """MCP Gateway — real-time proxy for traffic interception.

    Install the Medusa Gateway to transparently intercept MCP traffic
    between clients (Cursor, Claude Code) and servers, enforcing
    security policies, DLP, and audit logging in real-time.

    \b
    Commands:
      install    Route MCP traffic through the gateway
      uninstall  Restore original MCP client configs
      status     Show gateway installation status
      proxy      Run the gateway proxy (internal)
    """


@gateway_group.command("install")
@click.option(
    "--client",
    type=str,
    default=None,
    help="MCP client to install (cursor, claude_desktop, etc). Default: all.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would change without modifying files.",
)
@click.option(
    "--server",
    "server_names",
    multiple=True,
    help="Only proxy specific server(s) by name.",
)
@click.pass_context
def gateway_install(
    ctx: click.Context,
    client: str | None,
    dry_run: bool,
    server_names: tuple[str, ...],
) -> None:
    """Install the Medusa Gateway proxy for MCP clients.

    Rewrites MCP client configurations to route server connections
    through the Medusa Gateway, enabling real-time policy enforcement,
    DLP scanning, and audit logging.

    \b
    Examples:
      medusa gateway install                        Install for all clients
      medusa gateway install --client cursor         Install for Cursor only
      medusa gateway install --dry-run               Preview changes
      medusa gateway install --server my-db-server   Only proxy specific server
    """
    from medusa.gateway.config_rewriter import ConfigRewriter

    quiet = ctx.obj.get("quiet", False)
    rewriter = ConfigRewriter()

    # Determine which clients to install
    if client:
        clients_to_install = [client]
    else:
        available = rewriter.list_clients()
        clients_to_install = [c["client"] for c in available if c["exists"] and c["servers"] > 0]

    if not clients_to_install:
        console.print("  [yellow]No MCP client configs found.[/yellow]")
        return

    names = list(server_names) if server_names else None
    total_modified = 0

    for c in clients_to_install:
        result = rewriter.install(c, dry_run=dry_run, server_names=names)

        if "error" in result:
            if not quiet:
                console.print(f"  [red]✗ {c}:[/red] {result['error']}")
            continue

        modified = result.get("would_modify") or result.get("modified", [])
        if not modified:
            if not quiet:
                console.print(f"  [dim]{c}: No servers to modify[/dim]")
            continue

        total_modified += len(modified)
        if dry_run:
            if not quiet:
                console.print(
                    f"  [cyan]▸ {c}:[/cyan] Would proxy {len(modified)} server(s): "
                    f"[dim]{', '.join(modified)}[/dim]"
                )
        else:
            if not quiet:
                console.print(
                    f"  [green]▸ {c}:[/green] Gateway installed for {len(modified)} server(s): "
                    f"[dim]{', '.join(modified)}[/dim]"
                )
                if backup := result.get("backup"):
                    console.print(f"    [dim]Backup: {backup}[/dim]")

    if not quiet:
        if dry_run:
            console.print(
                f"\n  [cyan]Dry run complete:[/cyan] {total_modified} server(s) would be proxied."
            )
        elif total_modified:
            console.print(
                f"\n  [green]Gateway installed![/green] {total_modified} server(s) "
                f"now routed through Medusa."
            )
            console.print("  [dim]Restart your MCP clients for changes to take effect.[/dim]")


@gateway_group.command("uninstall")
@click.option(
    "--client",
    type=str,
    default=None,
    help="MCP client to uninstall (cursor, claude_desktop, etc). Default: all.",
)
@click.pass_context
def gateway_uninstall(ctx: click.Context, client: str | None) -> None:
    """Remove the Medusa Gateway proxy and restore original configs.

    \b
    Examples:
      medusa gateway uninstall                  Uninstall from all clients
      medusa gateway uninstall --client cursor  Uninstall from Cursor only
    """
    from medusa.gateway.config_rewriter import ConfigRewriter

    quiet = ctx.obj.get("quiet", False)
    rewriter = ConfigRewriter()

    if client:
        clients_to_uninstall = [client]
    else:
        available = rewriter.list_clients()
        clients_to_uninstall = [
            c["client"] for c in available if c["exists"] and c["gateway_installed"] > 0
        ]

    if not clients_to_uninstall:
        console.print("  [dim]No gateway installations found.[/dim]")
        return

    total_restored = 0
    for c in clients_to_uninstall:
        result = rewriter.uninstall(c)
        if "error" in result:
            if not quiet:
                console.print(f"  [red]✗ {c}:[/red] {result['error']}")
            continue

        restored = result.get("restored", [])
        if restored:
            total_restored += len(restored)
            if not quiet:
                console.print(
                    f"  [green]▸ {c}:[/green] Restored {len(restored)} server(s): "
                    f"[dim]{', '.join(restored)}[/dim]"
                )

    if not quiet and total_restored:
        console.print(f"\n  [green]Gateway removed![/green] {total_restored} server(s) restored.")
        console.print("  [dim]Restart your MCP clients for changes to take effect.[/dim]")


@gateway_group.command("status")
@click.pass_context
def gateway_status(ctx: click.Context) -> None:
    """Show gateway installation status for all MCP clients.

    \b
    Examples:
      medusa gateway status
    """
    from medusa.gateway.config_rewriter import ConfigRewriter

    quiet = ctx.obj.get("quiet", False)
    rewriter = ConfigRewriter()
    clients = rewriter.list_clients()

    if not quiet:
        table = Table(show_header=True, box=None, padding=(0, 2), pad_edge=False)
        table.add_column("Client", style="bold")
        table.add_column("Config", style="dim")
        table.add_column("Servers")
        table.add_column("Gateway")

        for c in clients:
            if not c["exists"]:
                table.add_row(
                    c["client"],
                    c["config_path"],
                    "[dim]—[/dim]",
                    "[dim]not installed[/dim]",
                )
                continue

            gw_status = (
                f"[green]{c['gateway_installed']}/{c['servers']} proxied[/green]"
                if c["gateway_installed"] > 0
                else "[dim]not installed[/dim]"
            )

            table.add_row(
                c["client"],
                c["config_path"],
                str(c["servers"]),
                gw_status,
            )

        console.print()
        console.print(
            Panel(
                table,
                title="[bold]Medusa Gateway Status[/bold]",
                border_style="bright_blue",
                padding=(1, 2),
            )
        )
        console.print()


@cli.command("gateway-proxy", hidden=True)
@click.argument("server_command", nargs=-1, required=True)
@click.option(
    "--policy-file",
    type=click.Path(exists=False),
    default=None,
    help="Path to gateway policy YAML.",
)
@click.option("--server-name", type=str, default=None, help="Name for this server.")
@click.pass_context
def gateway_proxy_cmd(
    ctx: click.Context,
    server_command: tuple[str, ...],
    policy_file: str | None,
    server_name: str | None,
) -> None:
    """Run the gateway proxy for a single MCP server (internal command).

    This command is invoked by rewritten MCP client configs. It spawns
    the real MCP server as a subprocess and proxies all JSON-RPC traffic
    through the Medusa policy engine.

    \b
    Usage (typically auto-invoked):
      medusa gateway-proxy -- npx -y @modelcontextprotocol/server-everything
    """
    from medusa.gateway.policy import PolicyEngine
    from medusa.gateway.proxy import StdioGatewayProxy

    cmd = list(server_command)
    # Strip leading "--" separator if present
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        click.echo("Error: No server command provided.", err=True)
        sys.exit(1)

    # Load policy
    policy = _load_gateway_policy(policy_file)
    engine = PolicyEngine(policy)

    name = server_name or " ".join(cmd[:2])
    proxy = StdioGatewayProxy(
        server_command=cmd,
        policy_engine=engine,
        server_name=name,
    )

    try:
        exit_code = asyncio.run(proxy.run())
    except KeyboardInterrupt:
        exit_code = 0

    sys.exit(exit_code)


def _load_gateway_policy(path: str | None = None) -> GatewayPolicy:
    """Load gateway policy from YAML file or return defaults."""
    import yaml

    from medusa.gateway.policy import GatewayPolicy

    # Try explicit path, then default location
    search_paths = []
    if path:
        search_paths.append(Path(path))
    search_paths.append(Path.home() / ".medusa" / "gateway-policy.yaml")

    for p in search_paths:
        if p.exists():
            try:
                raw = yaml.safe_load(p.read_text()) or {}
                policies = raw.get("policies", raw)
                return GatewayPolicy(
                    blocked_servers=policies.get("blocked_servers", []),
                    allowed_servers=policies.get("allowed_servers"),
                    blocked_tools=policies.get("blocked_tools", []),
                    blocked_tool_patterns=policies.get("blocked_tool_patterns", []),
                    max_calls_per_minute=policies.get("max_calls_per_minute", 0),
                    block_secrets=policies.get("data_protection", {}).get("block_secrets", True),
                    block_pii=policies.get("data_protection", {}).get("block_pii", False),
                    scan_responses=policies.get("data_protection", {}).get("scan_responses", True),
                    scan_code=policies.get("data_protection", {}).get("scan_code", False),
                    coaching_enabled=policies.get("coaching", {}).get("enabled", True),
                )
            except Exception:
                pass

    return GatewayPolicy()


if __name__ == "__main__":
    cli()
