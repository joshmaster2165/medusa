"""Agent installer — orchestrates install and uninstall.

Handles the full lifecycle: save config, discover clients, install
gateway proxy on all MCP servers, register with dashboard, and
start/stop the background daemon.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from medusa.agent.config_watcher import ConfigWatcher
from medusa.agent.daemon import save_agent_config
from medusa.agent.models import (
    AGENT_CONFIG_PATH,
    AGENT_DB_PATH,
    GATEWAY_POLICY_PATH,
    MEDUSA_DIR,
    AgentConfig,
)
from medusa.agent.platform.common import (
    get_daemon_manager,
    get_platform,
    is_agent_running,
    remove_pid_file,
)
from medusa.agent.store import AgentStore

logger = logging.getLogger(__name__)


class AgentInstaller:
    """Orchestrates full agent installation and removal."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        self._config = config or AgentConfig()

    def install(
        self,
        customer_id: str,
        api_key: str,
        *,
        skip_daemon: bool = False,
        skip_register: bool = False,
    ) -> dict[str, Any]:
        """Full installation flow:

        1. Create ~/.medusa/ directory
        2. Save agent config
        3. Initialize SQLite store
        4. Discover MCP clients and install gateway proxy
        5. Register with dashboard (optional)
        6. Start daemon (optional)
        """
        results: dict[str, Any] = {
            "success": False,
            "steps": [],
        }

        try:
            # 1. Create directory
            MEDUSA_DIR.mkdir(parents=True, exist_ok=True)
            results["steps"].append({"step": "create_dir", "status": "ok"})

            # 2. Save config
            self._config.customer_id = customer_id
            self._config.api_key = api_key
            from datetime import UTC, datetime

            self._config.installed_at = datetime.now(UTC).isoformat()
            save_agent_config(self._config)
            results["steps"].append({"step": "save_config", "status": "ok"})
            results["agent_id"] = self._config.agent_id

            # 3. Init store
            store = AgentStore()
            store.set_state("customer_id", customer_id)
            store.set_state("agent_id", self._config.agent_id)
            results["steps"].append({"step": "init_store", "status": "ok"})

            # 4. Install gateway on all MCP clients
            watcher = ConfigWatcher(store)
            install_result = watcher.force_install_all()
            results["steps"].append(
                {
                    "step": "install_gateway",
                    "status": "ok",
                    "installed": install_result.get("installed", []),
                    "errors": install_result.get("errors", []),
                }
            )
            results["servers_proxied"] = len(install_result.get("installed", []))

            # 5. Register with dashboard
            if not skip_register and api_key:
                reg_result = self._register_with_dashboard()
                results["steps"].append(
                    {
                        "step": "register",
                        "status": "ok" if reg_result.get("success") else "warn",
                        **reg_result,
                    }
                )

            # 6. Start daemon
            if not skip_daemon:
                daemon_result = self._start_daemon()
                results["steps"].append(
                    {
                        "step": "start_daemon",
                        "status": "ok" if daemon_result.get("success") else "warn",
                        **daemon_result,
                    }
                )

            results["success"] = True

        except Exception as e:
            logger.exception("Installation failed")
            results["error"] = str(e)

        return results

    def uninstall(self, *, keep_data: bool = False) -> dict[str, Any]:
        """Full uninstallation flow:

        1. Stop daemon
        2. Uninstall gateway from all MCP clients
        3. Clean up files (optional)
        """
        results: dict[str, Any] = {
            "success": False,
            "steps": [],
        }

        try:
            # 1. Stop daemon
            running, pid = is_agent_running()
            if running and pid:
                import os
                import signal

                os.kill(pid, signal.SIGTERM)
                results["steps"].append({"step": "stop_daemon", "status": "ok", "pid": pid})
            remove_pid_file()

            # Try platform-specific uninstall
            try:
                manager = get_daemon_manager()
                manager.uninstall()
                results["steps"].append({"step": "uninstall_daemon", "status": "ok"})
            except (NotImplementedError, Exception) as e:
                results["steps"].append(
                    {"step": "uninstall_daemon", "status": "skip", "reason": str(e)}
                )

            # 2. Uninstall gateway from all clients
            watcher = ConfigWatcher()
            uninstall_result = watcher.force_uninstall_all()
            results["steps"].append(
                {
                    "step": "uninstall_gateway",
                    "status": "ok",
                    "restored": uninstall_result.get("restored", []),
                }
            )

            # 3. Clean up files
            if not keep_data:
                for path in [AGENT_DB_PATH, AGENT_CONFIG_PATH, GATEWAY_POLICY_PATH]:
                    if path.exists():
                        path.unlink()
                results["steps"].append({"step": "cleanup", "status": "ok"})
            else:
                results["steps"].append({"step": "cleanup", "status": "skip"})

            results["success"] = True

        except Exception as e:
            logger.exception("Uninstallation failed")
            results["error"] = str(e)

        return results

    def _register_with_dashboard(self) -> dict[str, Any]:
        """Register this agent with the Medusa dashboard."""
        endpoint = f"{self._config.supabase_url.rstrip('/')}/functions/v1/agent-register"
        try:
            resp = httpx.post(
                endpoint,
                json={
                    "agent_id": self._config.agent_id,
                    "customer_id": self._config.customer_id,
                    "hostname": self._config.hostname,
                    "os_platform": self._config.os_platform,
                    "os_version": self._config.os_version,
                },
                headers={
                    "Authorization": f"Bearer {self._config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                return {"success": True}
            return {
                "success": False,
                "error": f"HTTP {resp.status_code}: {resp.text[:100]}",
            }
        except httpx.HTTPError as e:
            return {"success": False, "error": str(e)}

    def _start_daemon(self) -> dict[str, Any]:
        """Start the daemon using the platform-specific manager."""
        try:
            manager = get_daemon_manager()
            manager.install()
            manager.start()
            return {"success": True, "platform": get_platform()}
        except NotImplementedError:
            return {
                "success": False,
                "error": "Daemon not supported on this platform. Use 'medusa-agent run'.",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
