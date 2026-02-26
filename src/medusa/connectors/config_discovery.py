"""Auto-discover MCP servers from known configuration file locations."""

from __future__ import annotations

import json
import logging
import platform
from pathlib import Path

from medusa.connectors.base import BaseConnector
from medusa.connectors.http import HttpConnector
from medusa.connectors.stdio import StdioConnector

logger = logging.getLogger(__name__)

# Known MCP client config file locations
CONFIG_PATHS: dict[str, dict[str, str]] = {
    "claude_desktop": {
        "darwin": "~/Library/Application Support/Claude/claude_desktop_config.json",
        "win32": "%APPDATA%/Claude/claude_desktop_config.json",
        "linux": "~/.config/Claude/claude_desktop_config.json",
    },
    "cursor": {
        "darwin": "~/.cursor/mcp.json",
        "win32": "%APPDATA%/.cursor/mcp.json",
        "linux": "~/.cursor/mcp.json",
    },
}


def _expand_path(path_str: str) -> Path:
    """Expand ~ and environment variables in a path."""
    import os

    expanded = os.path.expandvars(os.path.expanduser(path_str))
    return Path(expanded)


def _build_connector(
    server_name: str,
    server_config: dict,
    config_file_path: str,
) -> BaseConnector | None:
    """Build a connector from a server config entry."""
    # stdio transport: has "command" key
    if "command" in server_config:
        return StdioConnector(
            name=server_name,
            command=server_config["command"],
            args=server_config.get("args", []),
            env=server_config.get("env", {}),
            config_file_path=config_file_path,
            config_raw=server_config,
        )

    # HTTP transport: has "url" key
    if "url" in server_config:
        return HttpConnector(
            name=server_name,
            url=server_config["url"],
            headers=server_config.get("headers", {}),
            config_file_path=config_file_path,
            config_raw=server_config,
        )

    logger.warning(
        "Server '%s' in '%s' has no recognized transport (no 'command' or 'url' key)",
        server_name,
        config_file_path,
    )
    return None


def discover_servers(
    additional_config_files: list[str] | None = None,
) -> list[BaseConnector]:
    """Auto-discover MCP servers from known config file locations.

    Returns a list of connectors ready to connect and snapshot.
    """
    connectors: list[BaseConnector] = []
    system = platform.system().lower()

    # Map platform names
    platform_key = {
        "darwin": "darwin",
        "windows": "win32",
        "linux": "linux",
    }.get(system, "linux")

    # Search known config file locations
    for client_name, paths in CONFIG_PATHS.items():
        path_str = paths.get(platform_key)
        if not path_str:
            continue

        config_path = _expand_path(path_str)
        if not config_path.exists():
            logger.debug("Config not found: %s (%s)", config_path, client_name)
            continue

        logger.info("Found config: %s (%s)", config_path, client_name)
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", config_path, e)
            continue

        servers = config.get("mcpServers", {})
        for server_name, server_config in servers.items():
            connector = _build_connector(
                server_name, server_config, str(config_path)
            )
            if connector:
                connectors.append(connector)

    # Search additional config files
    for extra_path in additional_config_files or []:
        config_path = _expand_path(extra_path)
        if not config_path.exists():
            logger.warning("Additional config not found: %s", config_path)
            continue

        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", config_path, e)
            continue

        servers = config.get("mcpServers", {})
        for server_name, server_config in servers.items():
            connector = _build_connector(
                server_name, server_config, str(config_path)
            )
            if connector:
                connectors.append(connector)

    logger.info("Discovered %d MCP server(s)", len(connectors))
    return connectors
