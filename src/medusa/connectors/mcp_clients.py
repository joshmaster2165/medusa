"""MCP client configuration paths and utilities.

Platform-aware discovery of MCP client config file locations
(Claude Desktop, Cursor, VS Code, Windsurf, etc.).  Used by the
gateway config-rewriter and agent config-watcher.
"""

from __future__ import annotations

import json
import logging
import os
import platform
from pathlib import Path

import yaml

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


def _get_platform_key() -> str:
    """Return the platform key for CONFIG_PATHS lookup."""
    system = platform.system().lower()
    return {
        "darwin": "darwin",
        "windows": "win32",
        "linux": "linux",
    }.get(system, "linux")


def _expand_path(path_str: str) -> Path:
    """Expand ~ and environment variables in a path."""
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
        servers = config.get("mcp", {}).get("servers", {})
    if not servers:
        servers = config.get("servers", {})
    return servers
