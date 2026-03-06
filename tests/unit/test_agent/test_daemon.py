"""Tests for agent daemon."""

from __future__ import annotations

from unittest.mock import patch

from medusa.agent.daemon import AgentDaemon, load_agent_config, save_agent_config
from medusa.agent.models import AgentConfig, AgentState
from medusa.agent.store import AgentStore


class TestLoadSaveConfig:
    """Tests for config persistence."""

    def test_save_and_load(self, tmp_path):
        config_path = tmp_path / "agent-config.yaml"
        config = AgentConfig(
            customer_id="test-customer",
            api_key="med_test123",
        )

        with patch("medusa.agent.daemon.AGENT_CONFIG_PATH", config_path):
            save_agent_config(config)
            loaded = load_agent_config()

        assert loaded.customer_id == "test-customer"
        assert loaded.api_key == "med_test123"

    def test_load_nonexistent_returns_defaults(self, tmp_path):
        config_path = tmp_path / "nonexistent.yaml"
        with patch("medusa.agent.daemon.AGENT_CONFIG_PATH", config_path):
            config = load_agent_config()
        assert config.customer_id == ""

    def test_save_creates_directory(self, tmp_path):
        config_path = tmp_path / "subdir" / "agent-config.yaml"
        config = AgentConfig(customer_id="test")

        with patch("medusa.agent.daemon.AGENT_CONFIG_PATH", config_path):
            save_agent_config(config)

        assert config_path.exists()


class TestAgentDaemon:
    """Tests for daemon initialization and properties."""

    def _make_daemon(self, tmp_path):
        config = AgentConfig(
            customer_id="test",
            api_key="key",
        )
        store = AgentStore(db_path=tmp_path / "test.db")
        return AgentDaemon(config=config, store=store)

    def test_init(self, tmp_path):
        daemon = self._make_daemon(tmp_path)
        assert daemon.state == AgentState.STOPPED
        assert daemon.config.customer_id == "test"

    def test_uptime_zero_initially(self, tmp_path):
        daemon = self._make_daemon(tmp_path)
        assert daemon.uptime == 0.0

    def test_store_accessible(self, tmp_path):
        daemon = self._make_daemon(tmp_path)
        assert daemon.store is not None

    def test_config_accessible(self, tmp_path):
        daemon = self._make_daemon(tmp_path)
        assert daemon.config.api_key == "key"

    def test_request_shutdown(self, tmp_path):
        daemon = self._make_daemon(tmp_path)
        # Access private method
        assert not daemon._shutdown_event.is_set()
        daemon._request_shutdown()
        assert daemon._shutdown_event.is_set()
