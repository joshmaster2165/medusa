"""Medusa CLI entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

import click
import httpx
from rich.console import Console
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


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="medusa")
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (-v, -vv, -vvv)",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="Suppress all output except errors",
)
@click.pass_context
def cli(ctx: click.Context, verbose: int, quiet: bool) -> None:
    """Medusa - Security scanner for MCP servers."""
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


@cli.command()
@click.option(
    "--config-file",
    type=str,
    default=None,
    help="Path to MCP config file",
)
@click.option(
    "--scan-config",
    type=str,
    default=None,
    help="Path to medusa.yaml",
)
@click.option(
    "--http",
    "http_url",
    type=str,
    default=None,
    help="Scan an HTTP MCP server by URL",
)
@click.option(
    "--stdio",
    "stdio_cmd",
    type=str,
    default=None,
    help="Scan a stdio MCP server by command",
)
@click.option(
    "--server",
    type=str,
    default=None,
    help="Scan a specific server by name from config",
)
@click.option(
    "-o",
    "--output",
    "output_format",
    type=click.Choice(["console", "json", "html", "markdown", "sarif"]),
    default="console",
    help="Output format (default: console for terminal, json for pipes)",
)
@click.option(
    "--output-file",
    type=str,
    default=None,
    help="Write output to file",
)
@click.option(
    "--category",
    type=str,
    default=None,
    help="Comma-separated categories to scan",
)
@click.option(
    "--severity",
    type=str,
    default=None,
    help="Minimum severity to report",
)
@click.option(
    "--checks",
    type=str,
    default=None,
    help="Comma-separated check IDs to run",
)
@click.option(
    "--exclude-checks",
    type=str,
    default=None,
    help="Comma-separated check IDs to exclude",
)
@click.option(
    "--fail-on",
    type=str,
    default="high",
    help="Min severity for non-zero exit code",
)
@click.option(
    "--compliance",
    type=str,
    default=None,
    help="Compliance framework to evaluate",
)
@click.option(
    "--no-auto-discover",
    is_flag=True,
    help="Disable auto-discovery of servers",
)
@click.option(
    "--max-concurrency",
    type=int,
    default=4,
    help="Max servers to scan concurrently (default: 4)",
)
@click.option(
    "--upload",
    is_flag=True,
    default=False,
    help="Upload results to configured dashboard (see 'medusa configure')",
)
@click.option(
    "--api-key",
    type=str,
    default=None,
    help="API key for dashboard upload (overrides MEDUSA_API_KEY and saved config)",
)
@click.option(
    "--ai-scan",
    is_flag=True,
    default=False,
    help="Enable AI-powered security analysis (requires credits)",
)
@click.option(
    "--claude-api-key",
    type=str,
    default=None,
    help="Anthropic API key for AI scanning (overrides ANTHROPIC_API_KEY)",
)
@click.option(
    "--ai-mode",
    type=click.Choice(["byok", "proxied"]),
    default=None,
    help="AI mode: use your own Claude key (byok) or dashboard proxy (proxied)",
)
@click.pass_context
def scan(
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
    ai_scan: bool,
    claude_api_key: str | None,
    ai_mode: str | None,
) -> None:
    """Scan MCP servers for security vulnerabilities."""
    quiet = ctx.obj.get("quiet", False)

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
            console.print("[yellow]No MCP servers found to scan.[/yellow]")
            console.print("Use --config-file, --http, or --stdio to specify servers.")
        sys.exit(3)

    if not quiet:
        console.print(f"[green]Found {len(connectors)} server(s) to scan[/green]")

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
    if ai_scan:
        _setup_ai_scan(
            ctx, ai_mode, claude_api_key, api_key, quiet
        )

    # Build the scan engine
    engine = ScanEngine(
        connectors=connectors,
        registry=registry,
        categories=categories,
        check_ids=check_ids,
        exclude_ids=exclude_ids,
        max_concurrency=max_concurrency,
        ai_enabled=ai_scan,
    )

    num_checks = len(engine.checks)
    total_work = len(connectors) * num_checks

    # Run scan with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
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
                    description=f"Scanning {detail}...",
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
                console.print(f"[yellow]Compliance framework not found: {compliance_name}[/yellow]")

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
            console.print(f"Report written to: {output_file}")
    else:
        reporter.print_to_console(result, console)

    # Upload results to dashboard
    if upload:
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
            console.print(
                "[red]API key required for --upload. Provide via --api-key, "
                "MEDUSA_API_KEY env var, or 'medusa configure'.[/red]"
            )
            sys.exit(2)

        if not quiet:
            console.print(f"\n[dim]Uploading results to {upload_url}...[/dim]")

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
                        "[green]Uploaded successfully to your"
                        f" dashboard at {dash}[/green]"
                    )
            else:
                try:
                    detail = resp.json().get("error", resp.text)
                except (ValueError, KeyError):
                    detail = resp.text[:200] or f"HTTP {resp.status_code}"
                console.print(f"[red]Upload failed ({resp.status_code}): {detail}[/red]")
        except httpx.HTTPError as exc:
            console.print(f"[red]Upload failed: {exc}[/red]")

    # Print summary for non-console formats (console reporter includes its own)
    if not quiet and effective_format != "console":
        console.print()
        _print_summary(result)

    # Exit code
    if has_findings_above_threshold(result, fail_on):
        sys.exit(1)


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
            console.print(
                "[red]Claude API key required for AI scanning. "
                "Provide via --claude-api-key, ANTHROPIC_API_KEY "
                "env var, or 'medusa configure'.[/red]"
            )
            sys.exit(2)

        client = ClaudeClient(
            api_key=resolved_claude_key,
            model=user_config.claude_model,
        )
    else:
        # Proxied mode — dashboard holds the Anthropic key
        if not medusa_key:
            console.print(
                "[red]Medusa API key required for proxied AI "
                "scanning. Run 'medusa configure'.[/red]"
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
            f"[cyan]AI scanning enabled ({mode_label} mode)[/cyan]"
        )


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
    console.print(f"Scanned {servers} server(s) in {duration}s")


@cli.command("list-checks")
@click.option(
    "--category",
    type=str,
    default=None,
    help="Filter by category",
)
@click.option(
    "--severity",
    type=str,
    default=None,
    help="Filter by severity",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
)
def list_checks(category: str | None, severity: str | None, fmt: str) -> None:
    """List all available security checks."""
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

    table = Table(
        title=f"Medusa Security Checks ({len(all_checks)})",
        show_header=True,
    )
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Category", style="magenta")
    table.add_column("Severity")
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
        table.add_row(
            meta.check_id,
            meta.title,
            meta.category,
            f"[{sev_style}]{meta.severity.value}[/{sev_style}]",
            owasp,
        )

    console.print(table)


@cli.command()
@click.option(
    "--api-key",
    type=str,
    default=None,
    help="Medusa dashboard API key",
)
@click.option(
    "--dashboard-url",
    type=str,
    default=None,
    help="Dashboard upload URL",
)
@click.option(
    "--claude-api-key",
    type=str,
    default=None,
    help="Anthropic API key for AI scanning",
)
@click.option(
    "--ai-mode",
    type=click.Choice(["byok", "proxied"]),
    default=None,
    help="AI mode: byok (your own key) or proxied (via dashboard)",
)
@click.pass_context
def configure(
    ctx: click.Context,
    api_key: str | None,
    dashboard_url: str | None,
    claude_api_key: str | None,
    ai_mode: str | None,
) -> None:
    """Save Medusa CLI configuration to ~/.medusa/config.yaml."""
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
        api_key = click.prompt(
            "Medusa API key",
            default=config.api_key or "",
            show_default=bool(config.api_key),
        )
        dashboard_url = click.prompt(
            "Dashboard URL",
            default=config.dashboard_url,
        )
        claude_api_key = click.prompt(
            "Anthropic API key (for AI scanning, optional)",
            default=config.claude_api_key or "",
            show_default=bool(config.claude_api_key),
        )
        ai_mode = click.prompt(
            "AI mode",
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
        console.print(
            f"[green]Configuration saved to {CONFIG_FILE}[/green]"
        )


@cli.command()
@click.pass_context
def settings(ctx: click.Context) -> None:
    """Display current Medusa CLI configuration."""
    from medusa.cli.config import CONFIG_FILE, load_user_config

    quiet = ctx.obj.get("quiet", False)
    config = load_user_config()

    if not quiet:
        console.print(f"[dim]Config file: {CONFIG_FILE}[/dim]")
        console.print()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold")
    table.add_column("Value")

    # Mask API key: show first 12 chars + "..."
    if config.api_key:
        masked = _mask_key(config.api_key)
        table.add_row("API Key", f"[green]{masked}[/green]")
    else:
        table.add_row("API Key", "[red]Not set[/red]")

    table.add_row("Dashboard URL", config.dashboard_url)

    # AI settings
    table.add_row("", "")  # spacer
    if config.claude_api_key:
        masked = _mask_key(config.claude_api_key)
        table.add_row(
            "Claude API Key", f"[green]{masked}[/green]"
        )
    else:
        table.add_row("Claude API Key", "[dim]Not set[/dim]")

    table.add_row("AI Mode", config.ai_mode)
    table.add_row("Claude Model", config.claude_model)

    console.print(table)


def _mask_key(key: str) -> str:
    """Mask a key: show first 12 chars + '...'."""
    if len(key) > 12:
        return key[:12] + "..."
    return key


if __name__ == "__main__":
    cli()
