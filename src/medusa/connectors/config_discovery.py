"""Auto-discover MCP servers from known configuration file locations."""

from __future__ import annotations

import json
import logging
import platform
from pathlib import Path

import yaml

from medusa.connectors.base import BaseConnector
from medusa.connectors.http import HttpConnector
from medusa.connectors.stdio import StdioConnector

logger = logging.getLogger(__name__)

# Human-readable display names for each client
CLIENT_DISPLAY_NAMES: dict[str, str] = {
    "claude_desktop": "Claude Desktop",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "vscode": "VS Code",
    "claude_code": "Claude Code",
    "gemini_cli": "Gemini CLI",
    "zed": "Zed",
    "cline": "Cline",
    "roo_code": "Roo Code",
    "continue_dev": "Continue.dev",
    "amazon_q": "Amazon Q",
    "copilot_vscode": "GitHub Copilot",
}

# Known MCP client config file locations
# Paths sourced from Snyk agent-scan's well_known_clients.py and verified
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
    "windsurf": {
        "darwin": "~/.codeium/windsurf/mcp_config.json",
        "win32": "%APPDATA%/Codeium/Windsurf/mcp_config.json",
        "linux": "~/.codeium/windsurf/mcp_config.json",
    },
    "vscode": {
        "darwin": "~/Library/Application Support/Code/User/settings.json",
        "win32": "%APPDATA%/Code/User/settings.json",
        "linux": "~/.config/Code/User/settings.json",
    },
    "claude_code": {
        "darwin": "~/.claude.json",
        "win32": "%USERPROFILE%/.claude.json",
        "linux": "~/.claude.json",
    },
    "gemini_cli": {
        "darwin": "~/.gemini/settings.json",
        "win32": "%APPDATA%/gemini/settings.json",
        "linux": "~/.config/gemini/settings.json",
    },
    "zed": {
        "darwin": "~/.config/zed/settings.json",
        "win32": "%APPDATA%/Zed/settings.json",
        "linux": "~/.config/zed/settings.json",
    },
    "cline": {
        "darwin": (
            "~/Library/Application Support/Code/User"
            "/globalStorage/saoudrizwan.claude-dev"
            "/settings/cline_mcp_settings.json"
        ),
        "win32": (
            "%APPDATA%/Code/User/globalStorage"
            "/saoudrizwan.claude-dev"
            "/settings/cline_mcp_settings.json"
        ),
        "linux": (
            "~/.config/Code/User/globalStorage"
            "/saoudrizwan.claude-dev"
            "/settings/cline_mcp_settings.json"
        ),
    },
    "roo_code": {
        "darwin": (
            "~/Library/Application Support/Code/User"
            "/globalStorage/rooveterinaryinc.roo-cline"
            "/settings/mcp_settings.json"
        ),
        "win32": (
            "%APPDATA%/Code/User/globalStorage"
            "/rooveterinaryinc.roo-cline"
            "/settings/mcp_settings.json"
        ),
        "linux": (
            "~/.config/Code/User/globalStorage"
            "/rooveterinaryinc.roo-cline"
            "/settings/mcp_settings.json"
        ),
    },
    "continue_dev": {
        "darwin": "~/.continue/config.yaml",
        "win32": "%USERPROFILE%/.continue/config.yaml",
        "linux": "~/.continue/config.yaml",
    },
    "amazon_q": {
        "darwin": "~/.aws/amazonq/mcp.json",
        "win32": "%USERPROFILE%/.aws/amazonq/mcp.json",
        "linux": "~/.aws/amazonq/mcp.json",
    },
    "copilot_vscode": {
        "darwin": ".vscode/mcp.json",
        "win32": ".vscode/mcp.json",
        "linux": ".vscode/mcp.json",
    },
}

# Project-level config paths (relative to cwd)
PROJECT_CONFIG_PATHS: dict[str, str] = {
    "copilot_vscode": ".vscode/mcp.json",
    "roo_code_project": ".roo/mcp.json",
    "amazon_q_project": ".amazonq/mcp.json",
}


def _expand_path(path_str: str) -> Path:
    """Expand ~ and environment variables in a path."""
    import os

    expanded = os.path.expandvars(os.path.expanduser(path_str))
    return Path(expanded)


def _parse_config_file(config_path: Path) -> dict | None:
    """Parse a config file (JSON or YAML) and return its contents."""
    try:
        text = config_path.read_text()
        if config_path.suffix in (".yaml", ".yml"):
            return yaml.safe_load(text) or {}
        return json.loads(text)
    except (json.JSONDecodeError, yaml.YAMLError, OSError) as e:
        logger.warning("Failed to parse %s: %s", config_path, e)
        return None


def _extract_servers(config: dict) -> dict:
    """Extract MCP server configs from a parsed JSON config.

    Handles multiple formats:
    - Standard: {"mcpServers": {...}}
    - VSCode:   {"mcp": {"servers": {...}}}
    - Copilot:  {"servers": {...}}
    """
    servers = config.get("mcpServers", {})
    if not servers:
        # VSCode format: mcp.servers key
        servers = config.get("mcp", {}).get("servers", {})
    if not servers:
        # Copilot / generic format: top-level servers key
        servers = config.get("servers", {})
    return servers


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


def _get_platform_key() -> str:
    """Return the platform key for CONFIG_PATHS lookup."""
    system = platform.system().lower()
    return {
        "darwin": "darwin",
        "windows": "win32",
        "linux": "linux",
    }.get(system, "linux")


def discover_servers(
    additional_config_files: list[str] | None = None,
) -> list[BaseConnector]:
    """Auto-discover MCP servers from known config file locations.

    Returns a list of connectors ready to connect and snapshot.
    """
    connectors: list[BaseConnector] = []
    platform_key = _get_platform_key()

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
        config = _parse_config_file(config_path)
        if config is None:
            continue

        servers = _extract_servers(config)
        for server_name, server_config in servers.items():
            connector = _build_connector(server_name, server_config, str(config_path))
            if connector:
                connectors.append(connector)

    # Search additional config files
    for extra_path in additional_config_files or []:
        config_path = _expand_path(extra_path)
        if not config_path.exists():
            logger.warning("Additional config not found: %s", config_path)
            continue

        config = _parse_config_file(config_path)
        if config is None:
            continue

        servers = _extract_servers(config)
        for server_name, server_config in servers.items():
            connector = _build_connector(server_name, server_config, str(config_path))
            if connector:
                connectors.append(connector)

    logger.info("Discovered %d MCP server(s)", len(connectors))
    return connectors


def discover_servers_detailed(
    include_project_configs: bool = True,
) -> dict[str, list[BaseConnector]]:
    """Auto-discover MCP servers, grouped by client name.

    Returns a dict mapping client display names to lists of connectors.
    Used by ``medusa quickscan`` for grouped display.
    """
    result: dict[str, list[BaseConnector]] = {}
    platform_key = _get_platform_key()
    seen_servers: set[str] = set()  # deduplicate by server name

    # Search known config file locations
    for client_key, paths in CONFIG_PATHS.items():
        path_str = paths.get(platform_key)
        if not path_str:
            continue

        config_path = _expand_path(path_str)
        if not config_path.exists():
            continue

        config = _parse_config_file(config_path)
        if config is None:
            continue

        display_name = CLIENT_DISPLAY_NAMES.get(client_key, client_key)
        servers = _extract_servers(config)
        for server_name, server_config in servers.items():
            if server_name in seen_servers:
                continue
            connector = _build_connector(server_name, server_config, str(config_path))
            if connector:
                result.setdefault(display_name, []).append(connector)
                seen_servers.add(server_name)

    # Search project-level configs
    if include_project_configs:
        for client_key, rel_path in PROJECT_CONFIG_PATHS.items():
            config_path = Path.cwd() / rel_path
            if not config_path.exists():
                continue

            config = _parse_config_file(config_path)
            if config is None:
                continue

            # Use base client display name
            base_key = client_key.replace("_project", "")
            display_name = CLIENT_DISPLAY_NAMES.get(base_key, base_key)
            display_name = f"{display_name} (project)"
            servers = _extract_servers(config)
            for server_name, server_config in servers.items():
                if server_name in seen_servers:
                    continue
                connector = _build_connector(server_name, server_config, str(config_path))
                if connector:
                    result.setdefault(display_name, []).append(connector)
                    seen_servers.add(server_name)

    return result
