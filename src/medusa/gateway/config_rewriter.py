"""Config rewriter for MCP client configurations.

Rewrites MCP client configs (Cursor, Claude Desktop, etc.) to route
server connections through the Medusa Gateway proxy.  Original configs
are backed up before modification.

Transforms server entries like:
    {"command": "npx", "args": ["-y", "@server/foo"]}
Into:
    {"command": "medusa-agent", "args": ["gateway-proxy", "--", "npx", "-y", "@server/foo"]}
"""

from __future__ import annotations

import json
import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from medusa.connectors.mcp_clients import CONFIG_PATHS, _get_platform_key

logger = logging.getLogger(__name__)


def _resolve_config_paths() -> dict[str, str]:
    """Resolve platform-specific CONFIG_PATHS to simple client→path dict."""
    platform_key = _get_platform_key()
    resolved: dict[str, str] = {}
    for client_name, paths in CONFIG_PATHS.items():
        path_str = paths.get(platform_key)
        if path_str:
            resolved[client_name] = path_str
    return resolved


# Marker key injected into rewritten server entries so we can detect
# and revert gateway-proxied servers.
GATEWAY_MARKER = "__medusa_gateway__"
BACKUP_SUFFIX = ".medusa-backup"


def _find_medusa_bin() -> str:
    """Find the medusa-agent CLI binary path."""
    import shutil as sh

    path = sh.which("medusa-agent")
    return path or "medusa-agent"


def rewrite_server_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a single MCP server config entry to route through the gateway.

    Only rewrites stdio-based entries (those with "command").
    HTTP entries (with "url") are left unchanged.
    """
    if "command" not in entry:
        return entry  # HTTP server — skip

    if entry.get(GATEWAY_MARKER):
        return entry  # Already rewritten

    original_command = entry["command"]
    original_args = entry.get("args", [])

    medusa = _find_medusa_bin()

    rewritten = {
        **entry,
        "command": medusa,
        "args": ["gateway-proxy", "--", original_command, *original_args],
        GATEWAY_MARKER: {
            "original_command": original_command,
            "original_args": original_args,
            "installed_at": datetime.now(UTC).isoformat(),
        },
    }

    return rewritten


def restore_server_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Restore a gateway-proxied entry to its original configuration."""
    marker = entry.get(GATEWAY_MARKER)
    if not marker:
        return entry  # Not a gateway entry

    restored = {k: v for k, v in entry.items() if k != GATEWAY_MARKER}
    restored["command"] = marker["original_command"]
    restored["args"] = marker.get("original_args", [])

    return restored


def is_gateway_installed(entry: dict[str, Any]) -> bool:
    """Check if a server entry is already routed through the gateway."""
    return bool(entry.get(GATEWAY_MARKER))


class ConfigRewriter:
    """Manages gateway installation/removal for MCP client configs."""

    def __init__(self) -> None:
        self._config_paths = _resolve_config_paths()

    def list_clients(self) -> list[dict[str, Any]]:
        """List all discoverable MCP clients and their config status."""
        results = []
        for client_name, path_str in self._config_paths.items():
            path = Path(path_str).expanduser()
            exists = path.exists()
            server_count = 0
            gateway_count = 0

            if exists:
                try:
                    data = json.loads(path.read_text())
                    servers = self._extract_servers(data)
                    server_count = len(servers)
                    gateway_count = sum(1 for s in servers.values() if is_gateway_installed(s))
                except (json.JSONDecodeError, OSError):
                    pass

            results.append(
                {
                    "client": client_name,
                    "config_path": str(path),
                    "exists": exists,
                    "servers": server_count,
                    "gateway_installed": gateway_count,
                }
            )
        return results

    def install(
        self,
        client: str,
        *,
        dry_run: bool = False,
        server_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Install the gateway proxy for a specific MCP client.

        Args:
            client: Client name (e.g., 'cursor', 'claude_desktop')
            dry_run: If True, show what would change without modifying files
            server_names: Optional list of specific server names to proxy.
                          If None, proxies all stdio servers.

        Returns:
            Dict with install results (servers modified, backup path, etc.)
        """
        path_str = self._config_paths.get(client)
        if not path_str:
            return {"error": f"Unknown client: {client}"}

        path = Path(path_str).expanduser()
        if not path.exists():
            return {"error": f"Config not found: {path}"}

        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            return {"error": f"Cannot read config: {e}"}

        servers = self._extract_servers(data)
        if not servers:
            return {"error": "No servers found in config"}

        modified = []
        for name, entry in servers.items():
            if server_names and name not in server_names:
                continue
            if is_gateway_installed(entry):
                continue
            if "command" not in entry:
                continue  # HTTP server — skip

            servers[name] = rewrite_server_entry(entry)
            modified.append(name)

        if not modified:
            return {"message": "No servers to modify", "modified": []}

        if dry_run:
            return {
                "dry_run": True,
                "would_modify": modified,
                "client": client,
            }

        # Backup original config
        backup_path = path.with_suffix(path.suffix + BACKUP_SUFFIX)
        shutil.copy2(path, backup_path)

        # Write modified config
        self._set_servers(data, servers)
        path.write_text(json.dumps(data, indent=2) + "\n")

        return {
            "success": True,
            "modified": modified,
            "backup": str(backup_path),
            "client": client,
        }

    def uninstall(self, client: str) -> dict[str, Any]:
        """Remove gateway proxy from a specific MCP client config."""
        path_str = self._config_paths.get(client)
        if not path_str:
            return {"error": f"Unknown client: {client}"}

        path = Path(path_str).expanduser()
        if not path.exists():
            return {"error": f"Config not found: {path}"}

        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            return {"error": f"Cannot read config: {e}"}

        servers = self._extract_servers(data)
        restored = []
        for name, entry in servers.items():
            if is_gateway_installed(entry):
                servers[name] = restore_server_entry(entry)
                restored.append(name)

        if not restored:
            return {"message": "No gateway entries found", "restored": []}

        # Write restored config
        self._set_servers(data, servers)
        path.write_text(json.dumps(data, indent=2) + "\n")

        # Remove backup if it exists
        backup_path = path.with_suffix(path.suffix + BACKUP_SUFFIX)
        if backup_path.exists():
            backup_path.unlink()

        return {
            "success": True,
            "restored": restored,
            "client": client,
        }

    def _extract_servers(self, data: dict) -> dict[str, dict]:
        """Extract server entries from a config dict.

        Handles multiple config formats:
        - {"mcpServers": {...}}        (Claude Desktop, Cursor)
        - {"mcp": {"servers": {...}}}  (VS Code / Copilot)
        - {"servers": {...}}           (generic)
        """
        if "mcpServers" in data:
            return data.get("mcpServers", {})
        if "mcp" in data and isinstance(data["mcp"], dict):
            return data["mcp"].get("servers", {})
        if "servers" in data:
            return data.get("servers", {})
        return {}

    def _set_servers(self, data: dict, servers: dict) -> None:
        """Set server entries back into a config dict."""
        if "mcpServers" in data:
            data["mcpServers"] = servers
        elif "mcp" in data and isinstance(data["mcp"], dict):
            data["mcp"]["servers"] = servers
        elif "servers" in data:
            data["servers"] = servers
        else:
            data["mcpServers"] = servers
