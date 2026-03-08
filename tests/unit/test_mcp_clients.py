"""Tests for the MCP client config paths and utilities."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from medusa.connectors.mcp_clients import (
    CLIENT_DISPLAY_NAMES,
    CONFIG_PATHS,
    PROJECT_CONFIG_PATHS,
    _expand_path,
    _extract_servers,
    _get_platform_key,
    _parse_config_file,
)


class TestConfigPaths:
    """Test config path constants."""

    def test_config_paths_has_known_clients(self):
        expected = {
            "claude_desktop",
            "cursor",
            "windsurf",
            "vscode",
            "claude_code",
        }
        assert expected.issubset(set(CONFIG_PATHS.keys()))

    def test_each_client_has_platform_keys(self):
        for client, paths in CONFIG_PATHS.items():
            assert isinstance(paths, dict), f"{client} should be a dict"
            # At least darwin should be present
            assert "darwin" in paths, f"{client} missing darwin path"

    def test_display_names_match_config_paths(self):
        for client in CONFIG_PATHS:
            assert client in CLIENT_DISPLAY_NAMES, f"{client} missing display name"

    def test_project_config_paths(self):
        assert isinstance(PROJECT_CONFIG_PATHS, dict)
        assert "copilot_vscode" in PROJECT_CONFIG_PATHS


class TestGetPlatformKey:
    def test_returns_string(self):
        key = _get_platform_key()
        assert key in ("darwin", "win32", "linux")

    @patch("medusa.connectors.mcp_clients.platform.system", return_value="Darwin")
    def test_darwin(self, _mock):
        assert _get_platform_key() == "darwin"

    @patch("medusa.connectors.mcp_clients.platform.system", return_value="Windows")
    def test_windows(self, _mock):
        assert _get_platform_key() == "win32"

    @patch("medusa.connectors.mcp_clients.platform.system", return_value="Linux")
    def test_linux(self, _mock):
        assert _get_platform_key() == "linux"

    @patch("medusa.connectors.mcp_clients.platform.system", return_value="FreeBSD")
    def test_unknown_defaults_linux(self, _mock):
        assert _get_platform_key() == "linux"


class TestExpandPath:
    def test_expands_tilde(self):
        result = _expand_path("~/test")
        assert "~" not in str(result)

    def test_returns_path(self):
        result = _expand_path("/some/path")
        assert isinstance(result, Path)


class TestParseConfigFile:
    def test_parse_json(self, tmp_path):
        f = tmp_path / "config.json"
        f.write_text(json.dumps({"mcpServers": {"s1": {}}}))
        result = _parse_config_file(f)
        assert result is not None
        assert "mcpServers" in result

    def test_parse_yaml(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("mcpServers:\n  s1:\n    command: npx\n")
        result = _parse_config_file(f)
        assert result is not None
        assert "mcpServers" in result

    def test_parse_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{invalid json")
        result = _parse_config_file(f)
        assert result is None

    def test_parse_missing_file(self, tmp_path):
        f = tmp_path / "nonexistent.json"
        result = _parse_config_file(f)
        assert result is None


class TestExtractServers:
    def test_mcp_servers_format(self):
        config = {"mcpServers": {"s1": {"command": "npx"}}}
        assert _extract_servers(config) == {"s1": {"command": "npx"}}

    def test_mcp_nested_format(self):
        config = {"mcp": {"servers": {"s1": {"command": "npx"}}}}
        assert _extract_servers(config) == {"s1": {"command": "npx"}}

    def test_servers_format(self):
        config = {"servers": {"s1": {"command": "npx"}}}
        assert _extract_servers(config) == {"s1": {"command": "npx"}}

    def test_empty_config(self):
        assert _extract_servers({}) == {}

    def test_priority_mcp_servers_first(self):
        config = {
            "mcpServers": {"s1": {"command": "npx"}},
            "servers": {"s2": {"command": "node"}},
        }
        # mcpServers takes priority
        result = _extract_servers(config)
        assert "s1" in result
