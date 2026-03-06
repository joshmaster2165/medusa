"""Tests for medusa.connectors.config_discovery — auto-discovery of MCP servers."""

from __future__ import annotations

import json
from unittest.mock import patch

import yaml

from medusa.connectors.config_discovery import (
    CLIENT_DISPLAY_NAMES,
    CONFIG_PATHS,
    PROJECT_CONFIG_PATHS,
    _build_connector,
    _extract_servers,
    _get_platform_key,
    _parse_config_file,
    discover_servers,
    discover_servers_detailed,
)
from medusa.connectors.http import HttpConnector
from medusa.connectors.stdio import StdioConnector

# ── CONFIG_PATHS structure ───────────────────────────────────────────────────


class TestConfigPaths:
    """Verify the CONFIG_PATHS dictionary structure."""

    def test_all_clients_have_display_names(self):
        """Every client in CONFIG_PATHS should have a display name."""
        for client_key in CONFIG_PATHS:
            assert client_key in CLIENT_DISPLAY_NAMES, f"Missing display name for '{client_key}'"

    def test_all_clients_have_three_platforms(self):
        """Every client should have darwin, win32, and linux paths."""
        for client_key, paths in CONFIG_PATHS.items():
            assert "darwin" in paths, f"{client_key} missing darwin"
            assert "win32" in paths, f"{client_key} missing win32"
            assert "linux" in paths, f"{client_key} missing linux"

    def test_original_eight_clients_present(self):
        """The original 8 clients must still be present."""
        original = [
            "claude_desktop",
            "cursor",
            "windsurf",
            "vscode",
            "claude_code",
            "gemini_cli",
            "zed",
            "cline",
        ]
        for name in original:
            assert name in CONFIG_PATHS

    def test_new_four_clients_present(self):
        """The 4 new clients must be present."""
        new = ["roo_code", "continue_dev", "amazon_q", "copilot_vscode"]
        for name in new:
            assert name in CONFIG_PATHS

    def test_total_client_count(self):
        """Should have exactly 12 clients."""
        assert len(CONFIG_PATHS) == 12

    def test_project_config_paths_exist(self):
        """Project-level config paths dict should have entries."""
        assert len(PROJECT_CONFIG_PATHS) >= 3
        assert "copilot_vscode" in PROJECT_CONFIG_PATHS
        assert "roo_code_project" in PROJECT_CONFIG_PATHS
        assert "amazon_q_project" in PROJECT_CONFIG_PATHS


# ── _get_platform_key ────────────────────────────────────────────────────────


class TestGetPlatformKey:
    def test_darwin(self):
        with patch("medusa.connectors.config_discovery.platform") as mock:
            mock.system.return_value = "Darwin"
            assert _get_platform_key() == "darwin"

    def test_windows(self):
        with patch("medusa.connectors.config_discovery.platform") as mock:
            mock.system.return_value = "Windows"
            assert _get_platform_key() == "win32"

    def test_linux(self):
        with patch("medusa.connectors.config_discovery.platform") as mock:
            mock.system.return_value = "Linux"
            assert _get_platform_key() == "linux"

    def test_unknown_defaults_to_linux(self):
        with patch("medusa.connectors.config_discovery.platform") as mock:
            mock.system.return_value = "FreeBSD"
            assert _get_platform_key() == "linux"


# ── _parse_config_file ───────────────────────────────────────────────────────


class TestParseConfigFile:
    def test_parse_json(self, tmp_path):
        f = tmp_path / "config.json"
        f.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}))
        result = _parse_config_file(f)
        assert result == {"mcpServers": {"a": {"command": "x"}}}

    def test_parse_yaml(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(yaml.dump({"mcpServers": {"b": {"url": "http://x"}}}))
        result = _parse_config_file(f)
        assert result == {"mcpServers": {"b": {"url": "http://x"}}}

    def test_parse_yml(self, tmp_path):
        f = tmp_path / "config.yml"
        f.write_text(yaml.dump({"servers": {"c": {"command": "z"}}}))
        result = _parse_config_file(f)
        assert result == {"servers": {"c": {"command": "z"}}}

    def test_parse_invalid_json_returns_none(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{invalid json")
        assert _parse_config_file(f) is None

    def test_parse_nonexistent_returns_none(self, tmp_path):
        f = tmp_path / "missing.json"
        assert _parse_config_file(f) is None

    def test_parse_empty_yaml_returns_empty_dict(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("")
        assert _parse_config_file(f) == {}


# ── _extract_servers ─────────────────────────────────────────────────────────


class TestExtractServers:
    def test_standard_format(self):
        config = {"mcpServers": {"s1": {"command": "x"}}}
        assert _extract_servers(config) == {"s1": {"command": "x"}}

    def test_vscode_format(self):
        config = {"mcp": {"servers": {"s2": {"url": "http://y"}}}}
        assert _extract_servers(config) == {"s2": {"url": "http://y"}}

    def test_copilot_servers_format(self):
        config = {"servers": {"s3": {"command": "z"}}}
        assert _extract_servers(config) == {"s3": {"command": "z"}}

    def test_empty_config(self):
        assert _extract_servers({}) == {}

    def test_standard_takes_priority(self):
        config = {
            "mcpServers": {"s1": {"command": "a"}},
            "servers": {"s2": {"command": "b"}},
        }
        assert _extract_servers(config) == {"s1": {"command": "a"}}


# ── _build_connector ─────────────────────────────────────────────────────────


class TestBuildConnector:
    def test_build_stdio_connector(self):
        c = _build_connector("test", {"command": "node", "args": ["-v"]}, "/cfg")
        assert isinstance(c, StdioConnector)
        assert c.name == "test"

    def test_build_http_connector(self):
        c = _build_connector("test", {"url": "http://localhost"}, "/cfg")
        assert isinstance(c, HttpConnector)
        assert c.name == "test"

    def test_unknown_transport_returns_none(self):
        c = _build_connector("test", {"foo": "bar"}, "/cfg")
        assert c is None


# ── discover_servers ─────────────────────────────────────────────────────────


class TestDiscoverServers:
    def test_discover_from_additional_config(self, tmp_path):
        """Additional config files are parsed and connectors returned."""
        f = tmp_path / "extra.json"
        f.write_text(json.dumps({"mcpServers": {"extra": {"command": "echo"}}}))
        connectors = discover_servers(additional_config_files=[str(f)])
        names = [c.name for c in connectors]
        assert "extra" in names

    def test_discover_yaml_config(self, tmp_path):
        """YAML config files are supported."""
        f = tmp_path / "extra.yaml"
        f.write_text(yaml.dump({"mcpServers": {"yml-srv": {"url": "http://x"}}}))
        connectors = discover_servers(additional_config_files=[str(f)])
        names = [c.name for c in connectors]
        assert "yml-srv" in names

    def test_missing_additional_config_is_skipped(self, tmp_path):
        # Clear CONFIG_PATHS so no real host configs are found
        with patch.dict("medusa.connectors.config_discovery.CONFIG_PATHS", {}, clear=True):
            connectors = discover_servers(additional_config_files=[str(tmp_path / "nope.json")])
            assert connectors == []

    def test_invalid_json_additional_config_is_skipped(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not valid json")
        with patch.dict("medusa.connectors.config_discovery.CONFIG_PATHS", {}, clear=True):
            connectors = discover_servers(additional_config_files=[str(f)])
            assert connectors == []


# ── discover_servers_detailed ────────────────────────────────────────────────


class TestDiscoverServersDetailed:
    def test_returns_dict(self):
        """Returns a dict, even if empty."""
        result = discover_servers_detailed(include_project_configs=False)
        assert isinstance(result, dict)

    def test_deduplicates_servers(self, tmp_path, monkeypatch):
        """Same server name across different clients is not duplicated."""
        config = json.dumps({"mcpServers": {"shared-server": {"command": "echo"}}})
        # Create two fake config files
        f1 = tmp_path / "client1.json"
        f1.write_text(config)
        f2 = tmp_path / "client2.json"
        f2.write_text(config)

        # Patch CONFIG_PATHS to use our test files
        test_paths = {
            "client_a": {"darwin": str(f1), "win32": str(f1), "linux": str(f1)},
            "client_b": {"darwin": str(f2), "win32": str(f2), "linux": str(f2)},
        }
        test_names = {"client_a": "Client A", "client_b": "Client B"}
        with (
            patch.dict(
                "medusa.connectors.config_discovery.CONFIG_PATHS",
                test_paths,
                clear=True,
            ),
            patch.dict(
                "medusa.connectors.config_discovery.CLIENT_DISPLAY_NAMES",
                test_names,
                clear=True,
            ),
        ):
            result = discover_servers_detailed(include_project_configs=False)
            # shared-server should only appear once
            all_connectors = [c for conns in result.values() for c in conns]
            names = [c.name for c in all_connectors]
            assert names.count("shared-server") == 1

    def test_project_configs_included(self, tmp_path, monkeypatch):
        """Project-level configs are discovered when flag is True."""
        monkeypatch.chdir(tmp_path)
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        mcp_file = vscode_dir / "mcp.json"
        mcp_file.write_text(json.dumps({"servers": {"copilot-srv": {"command": "node"}}}))

        # Clear global configs so only project configs are found
        with patch.dict("medusa.connectors.config_discovery.CONFIG_PATHS", {}, clear=True):
            result = discover_servers_detailed(include_project_configs=True)
            all_connectors = [c for conns in result.values() for c in conns]
            names = [c.name for c in all_connectors]
            assert "copilot-srv" in names

    def test_project_configs_excluded(self, tmp_path, monkeypatch):
        """Project-level configs are skipped when flag is False."""
        monkeypatch.chdir(tmp_path)
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        mcp_file = vscode_dir / "mcp.json"
        mcp_file.write_text(json.dumps({"servers": {"copilot-srv": {"command": "node"}}}))

        with patch.dict("medusa.connectors.config_discovery.CONFIG_PATHS", {}, clear=True):
            result = discover_servers_detailed(include_project_configs=False)
            assert result == {}
