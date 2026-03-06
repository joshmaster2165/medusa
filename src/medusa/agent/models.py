"""Data models for the Medusa Agent.

Defines configuration, telemetry events, agent status, and proxy
registration used across the daemon, store, and CLI.
"""

from __future__ import annotations

import platform
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

# ── Paths & Constants ────────────────────────────────────────────────

MEDUSA_DIR = Path.home() / ".medusa"
AGENT_DB_PATH = MEDUSA_DIR / "agent.db"
AGENT_CONFIG_PATH = MEDUSA_DIR / "agent-config.yaml"
GATEWAY_POLICY_PATH = MEDUSA_DIR / "gateway-policy.yaml"
PID_FILE_PATH = MEDUSA_DIR / "agent.pid"
LOG_DIR = MEDUSA_DIR / "logs"


class AgentState(StrEnum):
    """Lifecycle states for the agent daemon."""

    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class ProxyState(StrEnum):
    """State of a registered gateway proxy instance."""

    ACTIVE = "active"
    DEAD = "dead"
    UNKNOWN = "unknown"


# ── Agent Configuration ──────────────────────────────────────────────


class AgentConfig(BaseModel):
    """Persistent agent configuration.

    Stored at ~/.medusa/agent-config.yaml.
    Configured during ``medusa-agent install``.
    """

    # Identity
    customer_id: str = ""
    api_key: str = ""
    agent_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # Cloud connection
    supabase_url: str = "https://hgwytiwobyjhchpsimra.supabase.co"
    dashboard_url: str = "https://app.medusa.security"

    # Daemon behaviour
    telemetry_interval_seconds: int = 60
    telemetry_batch_size: int = 100
    policy_sync_interval_seconds: int = 300
    config_watch_interval_seconds: int = 30
    health_check_interval_seconds: int = 60

    # Feature flags
    telemetry_enabled: bool = True
    policy_sync_enabled: bool = True
    config_watch_enabled: bool = True

    # Install metadata
    installed_at: str = ""
    hostname: str = Field(default_factory=platform.node)
    os_platform: str = Field(default_factory=lambda: platform.system().lower())
    os_version: str = Field(default_factory=platform.version)


# ── Telemetry Event ──────────────────────────────────────────────────


class TelemetryEvent(BaseModel):
    """A single gateway event for upload to the dashboard.

    Written to ``agent.db`` by proxy processes, read by the
    daemon's telemetry manager for batched upload.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    agent_id: str = ""
    customer_id: str = ""

    # Message details
    direction: str = ""  # "request" | "response"
    message_type: str = ""  # e.g. "tools/call"
    method: str | None = None
    tool_name: str | None = None
    server_name: str = ""

    # Verdict
    verdict: str = ""  # "allow" | "block" | "coach"
    rule_name: str = ""
    reason: str = ""

    # Uploaded flag (managed by daemon)
    uploaded: bool = False


# ── Agent Status ─────────────────────────────────────────────────────


class AgentStatus(BaseModel):
    """Live status snapshot of the agent daemon.

    Built by the CLI ``status`` command from PID file + store data.
    """

    state: AgentState = AgentState.STOPPED
    pid: int | None = None
    uptime_seconds: float = 0.0

    # Counters (from store)
    events_total: int = 0
    events_pending_upload: int = 0
    proxies_registered: int = 0
    proxies_alive: int = 0

    # Config
    customer_id: str = ""
    agent_id: str = ""
    hostname: str = ""
    os_platform: str = ""


# ── Proxy Registration ───────────────────────────────────────────────


class ProxyRegistration(BaseModel):
    """A gateway proxy instance registered with the agent store.

    Proxies register on startup so the daemon can monitor
    their health and clean up stale entries.
    """

    pid: int
    server_name: str
    server_command: str = ""
    client_name: str = ""
    started_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_heartbeat: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    state: ProxyState = ProxyState.ACTIVE
