"""Tests for gateway config rewriter."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from medusa.gateway.config_rewriter import (
    GATEWAY_MARKER,
    ConfigRewriter,
    is_gateway_installed,
    restore_server_entry,
    rewrite_server_entry,
)

# ── rewrite_server_entry tests ─────────────────────────────────────────


class TestRewriteServerEntry:
    def test_rewrite_stdio_entry(self):
        entry = {"command": "npx", "args": ["-y", "@server/foo"]}
        medusa_bin = "/usr/local/bin/medusa"
        with patch("medusa.gateway.config_rewriter._find_medusa_bin", return_value=medusa_bin):
            result = rewrite_server_entry(entry)

        assert result["command"] == medusa_bin
        assert result["args"] == ["gateway-proxy", "--", "npx", "-y", "@server/foo"]
        assert GATEWAY_MARKER in result
        assert result[GATEWAY_MARKER]["original_command"] == "npx"
        assert result[GATEWAY_MARKER]["original_args"] == ["-y", "@server/foo"]
        assert "installed_at" in result[GATEWAY_MARKER]

    def test_skip_http_entry(self):
        entry = {"url": "http://localhost:8080/mcp"}
        result = rewrite_server_entry(entry)
        assert result == entry  # Unchanged
        assert GATEWAY_MARKER not in result

    def test_skip_already_rewritten(self):
        entry = {
            "command": "medusa",
            "args": ["gateway-proxy", "--", "npx", "server"],
            GATEWAY_MARKER: {
                "original_command": "npx",
                "original_args": ["server"],
                "installed_at": "2025-01-01T00:00:00Z",
            },
        }
        result = rewrite_server_entry(entry)
        assert result is entry  # Same object, not re-rewritten

    def test_preserves_extra_fields(self):
        entry = {
            "command": "python",
            "args": ["server.py"],
            "env": {"FOO": "bar"},
            "disabled": False,
        }
        with patch("medusa.gateway.config_rewriter._find_medusa_bin", return_value="medusa"):
            result = rewrite_server_entry(entry)

        assert result["env"] == {"FOO": "bar"}
        assert result["disabled"] is False

    def test_empty_args(self):
        entry = {"command": "my-server"}
        with patch("medusa.gateway.config_rewriter._find_medusa_bin", return_value="medusa"):
            result = rewrite_server_entry(entry)

        assert result["args"] == ["gateway-proxy", "--", "my-server"]
        assert result[GATEWAY_MARKER]["original_args"] == []


# ── restore_server_entry tests ─────────────────────────────────────────


class TestRestoreServerEntry:
    def test_restore_rewritten_entry(self):
        entry = {
            "command": "medusa",
            "args": ["gateway-proxy", "--", "npx", "-y", "@server/foo"],
            "env": {"FOO": "bar"},
            GATEWAY_MARKER: {
                "original_command": "npx",
                "original_args": ["-y", "@server/foo"],
                "installed_at": "2025-01-01T00:00:00Z",
            },
        }
        result = restore_server_entry(entry)
        assert result["command"] == "npx"
        assert result["args"] == ["-y", "@server/foo"]
        assert result["env"] == {"FOO": "bar"}
        assert GATEWAY_MARKER not in result

    def test_restore_non_gateway_entry(self):
        entry = {"command": "npx", "args": ["server"]}
        result = restore_server_entry(entry)
        assert result == entry

    def test_restore_without_original_args(self):
        entry = {
            "command": "medusa",
            "args": ["gateway-proxy", "--", "my-server"],
            GATEWAY_MARKER: {
                "original_command": "my-server",
                "installed_at": "2025-01-01T00:00:00Z",
            },
        }
        result = restore_server_entry(entry)
        assert result["command"] == "my-server"
        assert result["args"] == []


# ── is_gateway_installed tests ─────────────────────────────────────────


class TestIsGatewayInstalled:
    def test_installed(self):
        entry = {
            "command": "medusa",
            GATEWAY_MARKER: {"original_command": "npx"},
        }
        assert is_gateway_installed(entry) is True

    def test_not_installed(self):
        entry = {"command": "npx", "args": ["server"]}
        assert is_gateway_installed(entry) is False

    def test_empty_marker(self):
        entry = {"command": "medusa", GATEWAY_MARKER: {}}
        # Empty dict is falsy
        assert is_gateway_installed(entry) is False


# ── roundtrip tests ───────────────────────────────────────────────────


class TestRewriteRestoreRoundtrip:
    def test_roundtrip(self):
        original = {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-everything"],
            "env": {"NODE_ENV": "production"},
        }
        with patch("medusa.gateway.config_rewriter._find_medusa_bin", return_value="medusa"):
            rewritten = rewrite_server_entry(original.copy())

        assert rewritten["command"] == "medusa"
        assert is_gateway_installed(rewritten)

        restored = restore_server_entry(rewritten)
        assert restored["command"] == original["command"]
        assert restored["args"] == original["args"]
        assert restored["env"] == original["env"]
        assert not is_gateway_installed(restored)


# ── ConfigRewriter._extract_servers tests ─────────────────────────────


class TestExtractServers:
    """Tests for _extract_servers (indirectly via ConfigRewriter)."""

    def _make_rewriter(self):
        with patch("medusa.gateway.config_rewriter._resolve_config_paths", return_value={}):
            return ConfigRewriter()

    def test_mcp_servers_format(self):
        rewriter = self._make_rewriter()
        data = {"mcpServers": {"server1": {"command": "npx"}}}
        servers = rewriter._extract_servers(data)
        assert "server1" in servers

    def test_mcp_nested_format(self):
        rewriter = self._make_rewriter()
        data = {"mcp": {"servers": {"server1": {"command": "npx"}}}}
        servers = rewriter._extract_servers(data)
        assert "server1" in servers

    def test_servers_format(self):
        rewriter = self._make_rewriter()
        data = {"servers": {"server1": {"command": "npx"}}}
        servers = rewriter._extract_servers(data)
        assert "server1" in servers

    def test_no_servers(self):
        rewriter = self._make_rewriter()
        data = {"other": "stuff"}
        servers = rewriter._extract_servers(data)
        assert servers == {}


# ── ConfigRewriter._set_servers tests ─────────────────────────────────


class TestSetServers:
    def _make_rewriter(self):
        with patch("medusa.gateway.config_rewriter._resolve_config_paths", return_value={}):
            return ConfigRewriter()

    def test_set_mcp_servers(self):
        rewriter = self._make_rewriter()
        data = {"mcpServers": {}}
        new_servers = {"s1": {"command": "npx"}}
        rewriter._set_servers(data, new_servers)
        assert data["mcpServers"] == new_servers

    def test_set_mcp_nested(self):
        rewriter = self._make_rewriter()
        data = {"mcp": {"servers": {}}}
        new_servers = {"s1": {"command": "npx"}}
        rewriter._set_servers(data, new_servers)
        assert data["mcp"]["servers"] == new_servers

    def test_set_servers_key(self):
        rewriter = self._make_rewriter()
        data = {"servers": {}}
        new_servers = {"s1": {"command": "npx"}}
        rewriter._set_servers(data, new_servers)
        assert data["servers"] == new_servers

    def test_set_fallback_creates_mcp_servers(self):
        rewriter = self._make_rewriter()
        data = {}
        new_servers = {"s1": {"command": "npx"}}
        rewriter._set_servers(data, new_servers)
        assert data["mcpServers"] == new_servers


# ── ConfigRewriter install/uninstall with tmp files ───────────────────


class TestConfigRewriterInstallUninstall:
    """Integration tests using real temp files."""

    def _setup_config(self, tmp_path: Path, config_data: dict) -> tuple[ConfigRewriter, str]:
        """Create a temp config file and rewriter pointing to it."""
        config_path = tmp_path / "mcp.json"
        config_path.write_text(json.dumps(config_data, indent=2))

        with patch(
            "medusa.gateway.config_rewriter._resolve_config_paths",
            return_value={"test_client": str(config_path)},
        ):
            rewriter = ConfigRewriter()

        return rewriter, "test_client"

    def test_install(self, tmp_path):
        config = {
            "mcpServers": {
                "server1": {"command": "npx", "args": ["-y", "@server/foo"]},
                "server2": {"command": "python", "args": ["server.py"]},
            }
        }
        rewriter, client = self._setup_config(tmp_path, config)

        with patch("medusa.gateway.config_rewriter._find_medusa_bin", return_value="medusa"):
            result = rewriter.install(client)

        assert result.get("success") is True
        assert set(result["modified"]) == {"server1", "server2"}
        assert "backup" in result

        # Verify config was actually rewritten
        new_config = json.loads((tmp_path / "mcp.json").read_text())
        for name, entry in new_config["mcpServers"].items():
            assert entry["command"] == "medusa"
            assert GATEWAY_MARKER in entry

        # Verify backup was created
        backup = tmp_path / "mcp.json.medusa-backup"
        assert backup.exists()

    def test_install_dry_run(self, tmp_path):
        config = {
            "mcpServers": {
                "server1": {"command": "npx", "args": ["server"]},
            }
        }
        rewriter, client = self._setup_config(tmp_path, config)

        with patch("medusa.gateway.config_rewriter._find_medusa_bin", return_value="medusa"):
            result = rewriter.install(client, dry_run=True)

        assert result.get("dry_run") is True
        assert "server1" in result["would_modify"]

        # Verify config was NOT modified
        unchanged = json.loads((tmp_path / "mcp.json").read_text())
        assert GATEWAY_MARKER not in unchanged["mcpServers"]["server1"]

    def test_install_specific_servers(self, tmp_path):
        config = {
            "mcpServers": {
                "server1": {"command": "npx", "args": ["s1"]},
                "server2": {"command": "npx", "args": ["s2"]},
            }
        }
        rewriter, client = self._setup_config(tmp_path, config)

        with patch("medusa.gateway.config_rewriter._find_medusa_bin", return_value="medusa"):
            result = rewriter.install(client, server_names=["server1"])

        assert result["modified"] == ["server1"]

        new_config = json.loads((tmp_path / "mcp.json").read_text())
        assert GATEWAY_MARKER in new_config["mcpServers"]["server1"]
        assert GATEWAY_MARKER not in new_config["mcpServers"]["server2"]

    def test_install_skips_http_servers(self, tmp_path):
        config = {
            "mcpServers": {
                "stdio_server": {"command": "npx", "args": ["server"]},
                "http_server": {"url": "http://localhost:8080"},
            }
        }
        rewriter, client = self._setup_config(tmp_path, config)

        with patch("medusa.gateway.config_rewriter._find_medusa_bin", return_value="medusa"):
            result = rewriter.install(client)

        assert result["modified"] == ["stdio_server"]

    def test_install_skips_already_installed(self, tmp_path):
        config = {
            "mcpServers": {
                "server1": {
                    "command": "medusa",
                    "args": ["gateway-proxy", "--", "npx", "server"],
                    GATEWAY_MARKER: {
                        "original_command": "npx",
                        "original_args": ["server"],
                    },
                },
            }
        }
        rewriter, client = self._setup_config(tmp_path, config)

        result = rewriter.install(client)
        assert result.get("message") == "No servers to modify"

    def test_uninstall(self, tmp_path):
        config = {
            "mcpServers": {
                "server1": {
                    "command": "medusa",
                    "args": ["gateway-proxy", "--", "npx", "-y", "@server/foo"],
                    GATEWAY_MARKER: {
                        "original_command": "npx",
                        "original_args": ["-y", "@server/foo"],
                    },
                },
            }
        }
        rewriter, client = self._setup_config(tmp_path, config)

        # Create a backup file
        backup = tmp_path / "mcp.json.medusa-backup"
        backup.write_text("{}")

        result = rewriter.uninstall(client)

        assert result.get("success") is True
        assert result["restored"] == ["server1"]

        # Verify restored
        new_config = json.loads((tmp_path / "mcp.json").read_text())
        assert new_config["mcpServers"]["server1"]["command"] == "npx"
        assert GATEWAY_MARKER not in new_config["mcpServers"]["server1"]

        # Verify backup removed
        assert not backup.exists()

    def test_uninstall_no_gateway_entries(self, tmp_path):
        config = {
            "mcpServers": {
                "server1": {"command": "npx", "args": ["server"]},
            }
        }
        rewriter, client = self._setup_config(tmp_path, config)

        result = rewriter.uninstall(client)
        assert result.get("message") == "No gateway entries found"

    def test_install_unknown_client(self, tmp_path):
        with patch(
            "medusa.gateway.config_rewriter._resolve_config_paths",
            return_value={},
        ):
            rewriter = ConfigRewriter()

        result = rewriter.install("nonexistent")
        assert "error" in result

    def test_install_missing_config(self, tmp_path):
        with patch(
            "medusa.gateway.config_rewriter._resolve_config_paths",
            return_value={"test": str(tmp_path / "nonexistent.json")},
        ):
            rewriter = ConfigRewriter()

        result = rewriter.install("test")
        assert "error" in result

    def test_install_no_servers(self, tmp_path):
        config = {"mcpServers": {}}
        rewriter, client = self._setup_config(tmp_path, config)

        result = rewriter.install(client)
        assert "error" in result


# ── ConfigRewriter.list_clients tests ─────────────────────────────────


class TestListClients:
    def test_list_with_existing_config(self, tmp_path):
        config_path = tmp_path / "mcp.json"
        config = {
            "mcpServers": {
                "server1": {"command": "npx", "args": ["s1"]},
                "server2": {
                    "command": "medusa",
                    GATEWAY_MARKER: {"original_command": "npx"},
                },
            }
        }
        config_path.write_text(json.dumps(config))

        with patch(
            "medusa.gateway.config_rewriter._resolve_config_paths",
            return_value={"test_client": str(config_path)},
        ):
            rewriter = ConfigRewriter()

        clients = rewriter.list_clients()
        assert len(clients) == 1
        assert clients[0]["client"] == "test_client"
        assert clients[0]["exists"] is True
        assert clients[0]["servers"] == 2
        assert clients[0]["gateway_installed"] == 1

    def test_list_with_missing_config(self, tmp_path):
        with patch(
            "medusa.gateway.config_rewriter._resolve_config_paths",
            return_value={"missing": str(tmp_path / "nonexistent.json")},
        ):
            rewriter = ConfigRewriter()

        clients = rewriter.list_clients()
        assert len(clients) == 1
        assert clients[0]["exists"] is False
        assert clients[0]["servers"] == 0
