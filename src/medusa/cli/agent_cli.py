"""Medusa Agent CLI — ``medusa-agent`` command.

Provides install, uninstall, start, stop, restart, status, logs,
config, and version commands for the Medusa endpoint agent.
"""

from __future__ import annotations

import asyncio
import logging
import sys

import click
from rich.console import Console
from rich.table import Table

from medusa.agent.daemon import AgentDaemon, load_agent_config
from medusa.agent.installer import AgentInstaller
from medusa.agent.models import (
    AGENT_CONFIG_PATH,
    AGENT_DB_PATH,
    LOG_DIR,
)
from medusa.agent.platform.common import (
    get_platform,
    is_agent_running,
)
from medusa.agent.store import AgentStore

console = Console()
logger = logging.getLogger(__name__)


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
def agent_cli(debug: bool = False) -> None:
    """Medusa Agent — endpoint security for MCP."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


# ── Install / Uninstall ─────────────────────────────────────────────


@agent_cli.command()
@click.option("--customer-id", required=True, help="Your Medusa customer ID")
@click.option("--api-key", required=True, help="Your Medusa API key")
@click.option("--skip-daemon", is_flag=True, help="Don't start the background daemon")
@click.option("--skip-register", is_flag=True, help="Don't register with dashboard")
def install(
    customer_id: str,
    api_key: str,
    skip_daemon: bool,
    skip_register: bool,
) -> None:
    """Install the Medusa Agent on this machine."""
    console.print("\n[bold blue]Medusa Agent Installer[/bold blue]\n")

    installer = AgentInstaller()
    result = installer.install(
        customer_id=customer_id,
        api_key=api_key,
        skip_daemon=skip_daemon,
        skip_register=skip_register,
    )

    if result.get("success"):
        console.print("[green]Installation complete![/green]")
        console.print(f"  Agent ID:       {result.get('agent_id', 'n/a')}")
        console.print(f"  Customer ID:    {customer_id}")
        console.print(f"  Servers proxied: {result.get('servers_proxied', 0)}")
        console.print(f"  Config:         {AGENT_CONFIG_PATH}")
        console.print(f"  Database:       {AGENT_DB_PATH}")
        console.print()

        for step in result.get("steps", []):
            status = step.get("status", "?")
            icon = "[green]\u2713[/green]" if status == "ok" else "[yellow]![/yellow]"
            console.print(f"  {icon} {step['step']}")

    else:
        console.print(f"[red]Installation failed: {result.get('error', 'Unknown')}[/red]")
        sys.exit(1)


@agent_cli.command()
@click.option("--keep-data", is_flag=True, help="Keep agent data (db, config)")
def uninstall(keep_data: bool) -> None:
    """Uninstall the Medusa Agent from this machine."""
    console.print("\n[bold red]Medusa Agent Uninstaller[/bold red]\n")

    installer = AgentInstaller()
    result = installer.uninstall(keep_data=keep_data)

    if result.get("success"):
        console.print("[green]Uninstallation complete![/green]")
        for step in result.get("steps", []):
            status = step.get("status", "?")
            icon = "[green]\u2713[/green]" if status == "ok" else "[yellow]![/yellow]"
            console.print(f"  {icon} {step['step']}")
    else:
        console.print(f"[red]Uninstallation failed: {result.get('error', 'Unknown')}[/red]")
        sys.exit(1)


# ── Daemon Control ───────────────────────────────────────────────────


@agent_cli.command()
def start() -> None:
    """Start the agent daemon (via platform service)."""
    running, pid = is_agent_running()
    if running:
        console.print(f"[yellow]Agent is already running (PID {pid})[/yellow]")
        return

    try:
        from medusa.agent.platform.common import get_daemon_manager

        manager = get_daemon_manager()
        manager.start()
        console.print("[green]Agent daemon started[/green]")
    except NotImplementedError:
        console.print(
            "[yellow]Platform daemon not supported. "
            "Use 'medusa-agent run' for foreground mode.[/yellow]"
        )
    except Exception as e:
        console.print(f"[red]Failed to start daemon: {e}[/red]")
        sys.exit(1)


@agent_cli.command()
def stop() -> None:
    """Stop the agent daemon."""
    running, pid = is_agent_running()
    if not running:
        console.print("[yellow]Agent is not running[/yellow]")
        return

    import os
    import signal

    try:
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]Sent SIGTERM to agent (PID {pid})[/green]")
    except ProcessLookupError:
        console.print("[yellow]Agent process not found (stale PID file)[/yellow]")
        from medusa.agent.platform.common import remove_pid_file

        remove_pid_file()
    except Exception as e:
        console.print(f"[red]Failed to stop agent: {e}[/red]")
        sys.exit(1)


@agent_cli.command()
def restart() -> None:
    """Restart the agent daemon."""
    running, pid = is_agent_running()
    if running and pid:
        import os
        import signal

        os.kill(pid, signal.SIGTERM)
        console.print(f"Stopped agent (PID {pid})")

        import time

        time.sleep(2)

    try:
        from medusa.agent.platform.common import get_daemon_manager

        manager = get_daemon_manager()
        manager.start()
        console.print("[green]Agent daemon restarted[/green]")
    except Exception as e:
        console.print(f"[red]Failed to restart: {e}[/red]")
        sys.exit(1)


@agent_cli.command(name="run")
def run_foreground() -> None:
    """Run the agent in foreground mode (for debugging)."""
    console.print("[blue]Running Medusa Agent in foreground mode...[/blue]")
    console.print("Press Ctrl+C to stop.\n")

    config = load_agent_config()
    daemon = AgentDaemon(config=config)

    try:
        asyncio.run(daemon.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")


# ── Status / Info ────────────────────────────────────────────────────


@agent_cli.command()
def status() -> None:
    """Show agent status and health information."""
    running, pid = is_agent_running()
    config = load_agent_config()

    table = Table(title="Medusa Agent Status", show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    state = "[green]Running[/green]" if running else "[red]Stopped[/red]"
    table.add_row("State", state)
    table.add_row("PID", str(pid) if pid else "-")
    table.add_row("Agent ID", config.agent_id[:12] + "..." if config.agent_id else "-")
    table.add_row("Customer ID", config.customer_id or "-")
    table.add_row("Platform", get_platform())
    table.add_row("Hostname", config.hostname)
    table.add_row("Config", str(AGENT_CONFIG_PATH))
    table.add_row("Database", str(AGENT_DB_PATH))

    # Store stats
    if AGENT_DB_PATH.exists():
        try:
            store = AgentStore()
            total_events = store.count_events()
            pending = store.count_events(uploaded=False)
            proxies = store.list_proxies()

            table.add_row("Events (total)", str(total_events))
            table.add_row("Events (pending)", str(pending))
            table.add_row("Proxies registered", str(len(proxies)))
        except Exception:
            pass

    console.print()
    console.print(table)
    console.print()

    # Show proxy details
    if AGENT_DB_PATH.exists():
        try:
            from medusa.agent.health import HealthMonitor

            monitor = HealthMonitor(AgentStore())
            health = monitor.get_status()

            if health["total"] > 0:
                proxy_table = Table(title="Gateway Proxies")
                proxy_table.add_column("PID")
                proxy_table.add_column("Server")
                proxy_table.add_column("Client")
                proxy_table.add_column("State")
                proxy_table.add_column("Started")

                for p in health["proxies"]:
                    state_str = (
                        "[green]alive[/green]" if p["state"] == "alive" else "[red]dead[/red]"
                    )
                    proxy_table.add_row(
                        str(p["pid"]),
                        p["server_name"],
                        p["client_name"] or "-",
                        state_str,
                        p["started_at"][:19],
                    )
                console.print(proxy_table)
                console.print()
        except Exception:
            pass


@agent_cli.command()
@click.option("--lines", "-n", default=50, help="Number of log lines to show")
@click.option("--follow", "-f", is_flag=True, help="Follow log output")
def logs(lines: int, follow: bool) -> None:
    """Show agent log output."""
    log_file = LOG_DIR / "agent.log"
    if not log_file.exists():
        console.print("[yellow]No log file found[/yellow]")
        console.print(f"Expected at: {log_file}")
        return

    if follow:
        console.print(f"[dim]Following {log_file}...[/dim]")
        import subprocess

        subprocess.run(["tail", "-f", "-n", str(lines), str(log_file)])
    else:
        text = log_file.read_text()
        log_lines = text.strip().split("\n")
        for line in log_lines[-lines:]:
            console.print(line)


@agent_cli.command(name="config")
def show_config() -> None:
    """Show current agent configuration."""
    config = load_agent_config()
    console.print("\n[bold]Agent Configuration[/bold]\n")

    table = Table(show_header=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")

    # Show config fields (mask sensitive values)
    for key, value in config.model_dump().items():
        display_value = str(value)
        if key == "api_key" and value:
            display_value = value[:8] + "..." + value[-4:] if len(value) > 12 else "***"
        table.add_row(key, display_value)

    console.print(table)
    console.print(f"\n[dim]Config file: {AGENT_CONFIG_PATH}[/dim]\n")


@agent_cli.command()
def version() -> None:
    """Show agent version."""
    console.print("Medusa Agent v0.1.0")
    console.print(f"Platform: {get_platform()}")


# ── Entry point ──────────────────────────────────────────────────────

if __name__ == "__main__":
    agent_cli()
