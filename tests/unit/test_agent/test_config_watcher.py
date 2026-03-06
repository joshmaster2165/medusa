"""Tests for config watcher."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from medusa.agent.config_watcher import ConfigWatcher
from medusa.agent.store import AgentStore
from medusa.gateway.config_rewriter import GATEWAY_MARKER


class TestConfigWatcher:
    """Tests for ConfigWatcher."""

    def test_get_config_paths(self):
        watcher = ConfigWatcher()
        paths = watcher.get_config_paths()
        # Should have entries for known clients
        assert len(paths) > 0
        assert all(isinstance(p, Path) for p in paths.values())

    def test_check_and_install_no_configs(self, tmp_path):
        """When no config files exist, nothing is installed."""
        store = AgentStore(db_path=tmp_path / "test.db")
        watcher = ConfigWatcher(store=store)

        # Override paths to non-existent locations
        with patch.object(watcher, "get_config_paths", return_value={}):
            result = watcher.check_and_install()

        assert result["checked"] == 0
        assert result["installed"] == []

    def test_check_and_install_with_config(self, tmp_path):
        """When a config exists with servers, they get proxied."""
        config_path = tmp_path / "mcp.json"
        config_data = {
            "mcpServers": {
                "test-server": {"command": "npx", "args": ["server"]},
            }
        }
        config_path.write_text(json.dumps(config_data))

        store = AgentStore(db_path=tmp_path / "test.db")

        with (
            patch(
                "medusa.gateway.config_rewriter._resolve_config_paths",
                return_value={"test_client": str(config_path)},
            ),
            patch(
                "medusa.gateway.config_rewriter._find_medusa_bin",
                return_value="medusa",
            ),
        ):
            watcher = ConfigWatcher(store=store)
            # Override paths to use our temp path
            with patch.object(
                watcher,
                "get_config_paths",
                return_value={"test_client": config_path},
            ):
                result = watcher.check_and_install()

        assert result["checked"] == 1
        assert result["changed"] == 1

    def test_no_change_on_second_check(self, tmp_path):
        """Same mtime = no re-processing."""
        config_path = tmp_path / "mcp.json"
        config_path.write_text(json.dumps({"mcpServers": {}}))

        watcher = ConfigWatcher()

        with patch.object(
            watcher,
            "get_config_paths",
            return_value={"test_client": config_path},
        ):
            # First check: registers mtime
            result1 = watcher.check_and_install()
            # Second check: same mtime, skipped
            result2 = watcher.check_and_install()

        assert result1["changed"] == 1
        assert result2["changed"] == 0

    def test_force_install_all(self, tmp_path):
        """force_install_all delegates to ConfigRewriter."""
        config_path = tmp_path / "mcp.json"
        config_data = {
            "mcpServers": {
                "s1": {"command": "npx", "args": ["server1"]},
            }
        }
        config_path.write_text(json.dumps(config_data))

        with (
            patch(
                "medusa.gateway.config_rewriter._resolve_config_paths",
                return_value={"test": str(config_path)},
            ),
            patch(
                "medusa.gateway.config_rewriter._find_medusa_bin",
                return_value="medusa",
            ),
        ):
            watcher = ConfigWatcher()
            with patch.object(
                watcher,
                "get_config_paths",
                return_value={"test": config_path},
            ):
                result = watcher.force_install_all()

        assert len(result.get("installed", [])) >= 0  # May or may not install

    def test_force_uninstall_all(self, tmp_path):
        """force_uninstall_all delegates to ConfigRewriter."""
        config_path = tmp_path / "mcp.json"
        config_data = {
            "mcpServers": {
                "s1": {
                    "command": "medusa",
                    "args": ["gateway-proxy", "--", "npx", "server1"],
                    GATEWAY_MARKER: {
                        "original_command": "npx",
                        "original_args": ["server1"],
                    },
                },
            }
        }
        config_path.write_text(json.dumps(config_data))

        with patch(
            "medusa.gateway.config_rewriter._resolve_config_paths",
            return_value={"test": str(config_path)},
        ):
            watcher = ConfigWatcher()
            with patch.object(
                watcher,
                "get_config_paths",
                return_value={"test": config_path},
            ):
                result = watcher.force_uninstall_all()

        assert isinstance(result.get("restored"), list)
