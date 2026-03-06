"""Tests for agent installer."""

from __future__ import annotations

from unittest.mock import patch

from medusa.agent.installer import AgentInstaller
from medusa.agent.models import AgentConfig


class TestAgentInstaller:
    """Tests for AgentInstaller."""

    def test_install_basic(self, tmp_path):
        """Test basic install flow with all network ops skipped."""
        config = AgentConfig()

        with (
            patch("medusa.agent.installer.MEDUSA_DIR", tmp_path),
            patch("medusa.agent.installer.AGENT_CONFIG_PATH", tmp_path / "config.yaml"),
            patch("medusa.agent.installer.AGENT_DB_PATH", tmp_path / "agent.db"),
            patch("medusa.agent.installer.GATEWAY_POLICY_PATH", tmp_path / "policy.yaml"),
            patch("medusa.agent.daemon.AGENT_CONFIG_PATH", tmp_path / "config.yaml"),
            patch("medusa.agent.store.AGENT_DB_PATH", tmp_path / "agent.db"),
        ):
            installer = AgentInstaller(config=config)
            result = installer.install(
                customer_id="test-customer",
                api_key="med_test",
                skip_daemon=True,
                skip_register=True,
            )

        assert result["success"] is True
        assert result["agent_id"] == config.agent_id
        # Steps should include create_dir, save_config, init_store, install_gateway
        step_names = [s["step"] for s in result["steps"]]
        assert "create_dir" in step_names
        assert "save_config" in step_names
        assert "init_store" in step_names
        assert "install_gateway" in step_names

    def test_uninstall_basic(self, tmp_path):
        """Test basic uninstall flow."""
        # Create fake files
        (tmp_path / "agent.db").write_text("")
        (tmp_path / "config.yaml").write_text("")
        (tmp_path / "policy.yaml").write_text("")

        with (
            patch("medusa.agent.installer.MEDUSA_DIR", tmp_path),
            patch("medusa.agent.installer.AGENT_CONFIG_PATH", tmp_path / "config.yaml"),
            patch("medusa.agent.installer.AGENT_DB_PATH", tmp_path / "agent.db"),
            patch("medusa.agent.installer.GATEWAY_POLICY_PATH", tmp_path / "policy.yaml"),
            patch("medusa.agent.installer.is_agent_running", return_value=(False, None)),
            patch("medusa.agent.installer.remove_pid_file"),
            patch(
                "medusa.agent.installer.get_daemon_manager",
                side_effect=NotImplementedError,
            ),
        ):
            installer = AgentInstaller()
            result = installer.uninstall()

        assert result["success"] is True

    def test_install_sets_customer_id(self, tmp_path):
        """Verify customer_id is set on the config."""
        config = AgentConfig()

        with (
            patch("medusa.agent.installer.MEDUSA_DIR", tmp_path),
            patch("medusa.agent.installer.AGENT_CONFIG_PATH", tmp_path / "config.yaml"),
            patch("medusa.agent.installer.AGENT_DB_PATH", tmp_path / "agent.db"),
            patch("medusa.agent.installer.GATEWAY_POLICY_PATH", tmp_path / "policy.yaml"),
            patch("medusa.agent.daemon.AGENT_CONFIG_PATH", tmp_path / "config.yaml"),
            patch("medusa.agent.store.AGENT_DB_PATH", tmp_path / "agent.db"),
        ):
            installer = AgentInstaller(config=config)
            installer.install(
                customer_id="my-org",
                api_key="key123",
                skip_daemon=True,
                skip_register=True,
            )

        assert config.customer_id == "my-org"
        assert config.api_key == "key123"
