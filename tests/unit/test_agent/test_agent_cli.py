"""Tests for agent CLI commands."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from medusa.agent.models import AgentConfig


class TestAgentCLI:
    """Tests for agent_cli commands."""

    def test_version(self):
        from medusa.cli.agent_cli import agent_cli

        runner = CliRunner()
        result = runner.invoke(agent_cli, ["version"])
        assert result.exit_code == 0
        assert "Medusa Agent" in result.output

    def test_config_command(self, tmp_path):
        from medusa.cli.agent_cli import agent_cli

        config = AgentConfig(customer_id="test-org", api_key="med_test123")

        with patch(
            "medusa.cli.agent_cli.load_agent_config",
            return_value=config,
        ):
            runner = CliRunner()
            result = runner.invoke(agent_cli, ["config"])

        assert result.exit_code == 0
        assert "test-org" in result.output

    def test_status_not_running(self, tmp_path):
        from medusa.cli.agent_cli import agent_cli

        config = AgentConfig(customer_id="test-org")

        with (
            patch(
                "medusa.cli.agent_cli.is_agent_running",
                return_value=(False, None),
            ),
            patch(
                "medusa.cli.agent_cli.load_agent_config",
                return_value=config,
            ),
            patch(
                "medusa.cli.agent_cli.AGENT_DB_PATH",
                tmp_path / "nonexistent.db",
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(agent_cli, ["status"])

        assert result.exit_code == 0
        assert "Stopped" in result.output

    def test_stop_not_running(self):
        from medusa.cli.agent_cli import agent_cli

        with patch(
            "medusa.cli.agent_cli.is_agent_running",
            return_value=(False, None),
        ):
            runner = CliRunner()
            result = runner.invoke(agent_cli, ["stop"])

        assert result.exit_code == 0
        assert "not running" in result.output

    def test_help(self):
        from medusa.cli.agent_cli import agent_cli

        runner = CliRunner()
        result = runner.invoke(agent_cli, ["--help"])
        assert result.exit_code == 0
        assert "endpoint security" in result.output.lower()

    def test_monitor_command(self, tmp_path):
        """Test monitor command runs and shows posture info."""
        from medusa.cli.agent_cli import agent_cli

        with (
            patch(
                "medusa.agent.config_monitor.CONFIG_PATHS",
                {},
            ),
            patch(
                "medusa.gateway.policy.load_gateway_policy",
                return_value=type(
                    "P",
                    (),
                    {
                        "block_secrets": True,
                        "block_pii": False,
                        "max_calls_per_minute": 0,
                    },
                )(),
            ),
            patch(
                "medusa.cli.agent_cli.AGENT_DB_PATH",
                tmp_path / "nonexistent.db",
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(agent_cli, ["monitor"])

        assert result.exit_code == 0
        assert "Security Posture" in result.output

    def test_gateway_proxy_no_command(self):
        """Test gateway-proxy with no command shows error."""
        from medusa.cli.agent_cli import agent_cli

        runner = CliRunner()
        result = runner.invoke(agent_cli, ["gateway-proxy"])
        # Click requires at least one argument
        assert result.exit_code != 0

    def test_monitor_shows_in_help(self):
        """monitor should be visible in CLI help."""
        from medusa.cli.agent_cli import agent_cli

        runner = CliRunner()
        result = runner.invoke(agent_cli, ["--help"])
        assert "monitor" in result.output

    def test_gateway_proxy_hidden_in_help(self):
        """gateway-proxy should be hidden from CLI help."""
        from medusa.cli.agent_cli import agent_cli

        runner = CliRunner()
        result = runner.invoke(agent_cli, ["--help"])
        assert "gateway-proxy" not in result.output
