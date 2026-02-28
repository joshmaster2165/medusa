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
    type=str,
    default=None,
    is_flag=False,
    flag_value="__default__",
    help="Upload results to dashboard (optionally provide custom URL)",
)
@click.option(
    "--api-key",
    type=str,
    default=None,
    help="API key for dashboard upload (overrides MEDUSA_API_KEY and saved config)",
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
    upload: str | None,
    api_key: str | None,
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

    # Build the scan engine
    engine = ScanEngine(
        connectors=connectors,
        registry=registry,
        categories=categories,
        check_ids=check_ids,
        exclude_ids=exclude_ids,
        max_concurrency=max_concurrency,
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

        # Resolve upload URL: explicit arg > saved config > default
        if upload == "__default__":
            upload_url = user_config.dashboard_url
        else:
            upload_url = upload

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
                data = resp.json()
                if not quiet:
                    console.print(
                        f"[green]Uploaded successfully.[/green]"
                        f" View at: {data.get('scan_url', '')}"
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
@click.pass_context
def configure(
    ctx: click.Context,
    api_key: str | None,
    dashboard_url: str | None,
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
    if api_key is None and dashboard_url is None:
        api_key = click.prompt(
            "API key",
            default=config.api_key or "",
            show_default=bool(config.api_key),
        )
        dashboard_url = click.prompt(
            "Dashboard URL",
            default=config.dashboard_url,
        )

    if api_key is not None:
        config.api_key = api_key
    if dashboard_url is not None:
        config.dashboard_url = dashboard_url

    save_user_config(config)

    if not quiet:
        console.print(f"[green]Configuration saved to {CONFIG_FILE}[/green]")


if __name__ == "__main__":
    cli()
