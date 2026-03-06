"""Tests for agent data models."""

from __future__ import annotations

from medusa.agent.models import (
    AGENT_CONFIG_PATH,
    AGENT_DB_PATH,
    GATEWAY_POLICY_PATH,
    LOG_DIR,
    MEDUSA_DIR,
    AgentConfig,
    AgentState,
    AgentStatus,
    ProxyRegistration,
    ProxyState,
    TelemetryEvent,
)


class TestPaths:
    """Tests for path constants."""

    def test_medusa_dir(self):
        assert str(MEDUSA_DIR).endswith(".medusa")

    def test_agent_db_path(self):
        assert str(AGENT_DB_PATH).endswith("agent.db")

    def test_config_path(self):
        assert str(AGENT_CONFIG_PATH).endswith("agent-config.yaml")

    def test_policy_path(self):
        assert str(GATEWAY_POLICY_PATH).endswith("gateway-policy.yaml")

    def test_log_dir(self):
        assert str(LOG_DIR).endswith("logs")


class TestAgentState:
    def test_values(self):
        assert AgentState.STARTING == "starting"
        assert AgentState.RUNNING == "running"
        assert AgentState.STOPPING == "stopping"
        assert AgentState.STOPPED == "stopped"
        assert AgentState.ERROR == "error"


class TestProxyState:
    def test_values(self):
        assert ProxyState.ACTIVE == "active"
        assert ProxyState.DEAD == "dead"
        assert ProxyState.UNKNOWN == "unknown"


class TestAgentConfig:
    def test_defaults(self):
        config = AgentConfig()
        assert config.customer_id == ""
        assert config.api_key == ""
        assert config.agent_id != ""  # Auto-generated UUID
        assert config.telemetry_interval_seconds == 60
        assert config.telemetry_batch_size == 100
        assert config.policy_sync_interval_seconds == 300
        assert config.config_watch_interval_seconds == 30
        assert config.health_check_interval_seconds == 60
        assert config.telemetry_enabled is True
        assert config.policy_sync_enabled is True
        assert config.config_watch_enabled is True

    def test_custom_values(self):
        config = AgentConfig(
            customer_id="cust-123",
            api_key="med_test",
            telemetry_interval_seconds=30,
        )
        assert config.customer_id == "cust-123"
        assert config.api_key == "med_test"
        assert config.telemetry_interval_seconds == 30

    def test_unique_agent_ids(self):
        """Each config should get a unique agent_id."""
        c1 = AgentConfig()
        c2 = AgentConfig()
        assert c1.agent_id != c2.agent_id

    def test_hostname_populated(self):
        config = AgentConfig()
        assert config.hostname != ""

    def test_os_platform_populated(self):
        config = AgentConfig()
        assert config.os_platform in ("darwin", "linux", "windows")

    def test_supabase_url_default(self):
        config = AgentConfig()
        assert "supabase.co" in config.supabase_url


class TestTelemetryEvent:
    def test_defaults(self):
        event = TelemetryEvent()
        assert event.id != ""
        assert event.timestamp != ""
        assert event.uploaded is False
        assert event.direction == ""
        assert event.verdict == ""

    def test_custom_values(self):
        event = TelemetryEvent(
            direction="request",
            message_type="tools/call",
            tool_name="read_file",
            server_name="test-server",
            verdict="block",
            rule_name="tool_blocked",
            reason="Blocked by policy",
        )
        assert event.direction == "request"
        assert event.verdict == "block"
        assert event.tool_name == "read_file"

    def test_unique_ids(self):
        e1 = TelemetryEvent()
        e2 = TelemetryEvent()
        assert e1.id != e2.id


class TestAgentStatus:
    def test_defaults(self):
        status = AgentStatus()
        assert status.state == AgentState.STOPPED
        assert status.pid is None
        assert status.uptime_seconds == 0.0
        assert status.events_total == 0
        assert status.proxies_registered == 0

    def test_running_status(self):
        status = AgentStatus(
            state=AgentState.RUNNING,
            pid=12345,
            uptime_seconds=3600.0,
            events_total=500,
            events_pending_upload=42,
            proxies_registered=3,
            proxies_alive=2,
        )
        assert status.state == AgentState.RUNNING
        assert status.pid == 12345
        assert status.events_pending_upload == 42


class TestProxyRegistration:
    def test_defaults(self):
        reg = ProxyRegistration(
            pid=12345,
            server_name="test-server",
        )
        assert reg.pid == 12345
        assert reg.server_name == "test-server"
        assert reg.state == ProxyState.ACTIVE
        assert reg.started_at != ""
        assert reg.last_heartbeat != ""

    def test_with_all_fields(self):
        reg = ProxyRegistration(
            pid=99999,
            server_name="mcp-server",
            server_command="npx -y @server/foo",
            client_name="cursor",
        )
        assert reg.server_command == "npx -y @server/foo"
        assert reg.client_name == "cursor"
