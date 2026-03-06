"""Config watcher for auto-proxying MCP server entries.

Polls known MCP client config file paths for changes and
automatically installs the gateway proxy on new stdio servers.
Uses mtime-based change detection to avoid unnecessary reads.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from medusa.agent.store import AgentStore
from medusa.connectors.config_discovery import CONFIG_PATHS, _get_platform_key
from medusa.gateway.config_rewriter import ConfigRewriter

logger = logging.getLogger(__name__)


class ConfigWatcher:
    """Watches MCP client config files for changes and auto-proxies.

    Uses mtime polling (not filesystem events) for simplicity
    and cross-platform support.
    """

    def __init__(self, store: AgentStore | None = None) -> None:
        self._store = store
        self._rewriter = ConfigRewriter()
        self._mtimes: dict[str, float] = {}
        self._platform_key = _get_platform_key()

    def get_config_paths(self) -> dict[str, Path]:
        """Get all MCP config paths for the current platform."""
        paths: dict[str, Path] = {}
        for client_name, client_paths in CONFIG_PATHS.items():
            path_str = client_paths.get(self._platform_key)
            if path_str:
                expanded = Path(path_str).expanduser()
                paths[client_name] = expanded
        return paths

    def check_and_install(self) -> dict[str, Any]:
        """Check all configs for changes and install gateway on new servers.

        Returns a summary of actions taken.
        """
        results: dict[str, Any] = {
            "checked": 0,
            "changed": 0,
            "installed": [],
            "errors": [],
        }

        paths = self.get_config_paths()

        for client_name, config_path in paths.items():
            if not config_path.exists():
                continue

            results["checked"] += 1

            # Check mtime for changes
            try:
                current_mtime = config_path.stat().st_mtime
            except OSError:
                continue

            last_mtime = self._mtimes.get(client_name, 0.0)
            if current_mtime == last_mtime:
                continue  # No change

            self._mtimes[client_name] = current_mtime
            results["changed"] += 1

            # Try to install gateway on any new stdio servers
            try:
                install_result = self._rewriter.install(client_name)
                if install_result.get("success"):
                    modified = install_result.get("modified", [])
                    if modified:
                        results["installed"].extend(
                            [{"client": client_name, "server": s} for s in modified]
                        )
                        logger.info(
                            "Auto-proxied %d server(s) in %s: %s",
                            len(modified),
                            client_name,
                            ", ".join(modified),
                        )
                elif install_result.get("error"):
                    # Not an error worth logging if it's just "no servers"
                    pass
            except Exception as e:
                results["errors"].append({"client": client_name, "error": str(e)})
                logger.warning("Failed to auto-proxy %s: %s", client_name, e)

        return results

    def get_all_servers_status(self) -> list[dict[str, Any]]:
        """Get status of all servers across all MCP clients.

        Returns a list of dicts with client, server name, and gateway status.
        """
        return self._rewriter.list_clients()

    def force_install(self, client_name: str) -> dict[str, Any]:
        """Force gateway install on a specific client."""
        return self._rewriter.install(client_name)

    def force_uninstall(self, client_name: str) -> dict[str, Any]:
        """Force gateway uninstall on a specific client."""
        return self._rewriter.uninstall(client_name)

    def force_install_all(self) -> dict[str, Any]:
        """Force gateway install on all discovered clients."""
        results: dict[str, Any] = {"installed": [], "errors": []}
        paths = self.get_config_paths()

        for client_name in paths:
            try:
                result = self._rewriter.install(client_name)
                if result.get("success"):
                    results["installed"].extend(
                        [{"client": client_name, "server": s} for s in result.get("modified", [])]
                    )
            except Exception as e:
                results["errors"].append({"client": client_name, "error": str(e)})

        return results

    def force_uninstall_all(self) -> dict[str, Any]:
        """Force gateway uninstall on all discovered clients."""
        results: dict[str, Any] = {"restored": [], "errors": []}
        paths = self.get_config_paths()

        for client_name in paths:
            try:
                result = self._rewriter.uninstall(client_name)
                if result.get("success"):
                    results["restored"].extend(
                        [{"client": client_name, "server": s} for s in result.get("restored", [])]
                    )
            except Exception as e:
                results["errors"].append({"client": client_name, "error": str(e)})

        return results
