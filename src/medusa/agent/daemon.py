"""Medusa Agent daemon — main orchestrator.

Runs as a persistent background process (via launchd/Windows Service)
and coordinates:
- Config watching: auto-proxy new MCP server entries
- Telemetry: batch-upload events from SQLite to Supabase
- Policy sync: fetch policies from the dashboard
- Health monitoring: check proxy process liveness
"""

from __future__ import annotations

import asyncio
import logging
import time

import yaml

from medusa.agent.models import (
    AGENT_CONFIG_PATH,
    AgentConfig,
    AgentState,
)
from medusa.agent.platform.common import (
    install_signal_handlers,
    remove_pid_file,
    write_pid_file,
)
from medusa.agent.store import AgentStore

logger = logging.getLogger(__name__)


def load_agent_config() -> AgentConfig:
    """Load agent config from ~/.medusa/agent-config.yaml."""
    if AGENT_CONFIG_PATH.exists():
        raw = yaml.safe_load(AGENT_CONFIG_PATH.read_text())
        if raw:
            return AgentConfig.model_validate(raw)
    return AgentConfig()


def save_agent_config(config: AgentConfig) -> None:
    """Persist agent config to ~/.medusa/agent-config.yaml."""
    AGENT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    AGENT_CONFIG_PATH.write_text(
        yaml.dump(config.model_dump(exclude_none=True), default_flow_style=False)
    )


class AgentDaemon:
    """Main agent daemon orchestrator.

    Runs an asyncio event loop with concurrent subtasks for config
    watching, telemetry upload, policy sync, and health checks.
    """

    def __init__(
        self,
        config: AgentConfig | None = None,
        store: AgentStore | None = None,
    ) -> None:
        self._config = config or load_agent_config()
        self._store = store or AgentStore()
        self._state = AgentState.STOPPED
        self._shutdown_event = asyncio.Event()
        self._start_time: float = 0.0

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def config(self) -> AgentConfig:
        return self._config

    @property
    def store(self) -> AgentStore:
        return self._store

    @property
    def uptime(self) -> float:
        if self._start_time == 0:
            return 0.0
        return time.monotonic() - self._start_time

    async def run(self) -> None:
        """Run the daemon until shutdown is signalled."""
        self._state = AgentState.STARTING
        self._start_time = time.monotonic()

        # Write PID file
        write_pid_file()

        # Install signal handlers for graceful shutdown
        install_signal_handlers(self._request_shutdown)

        # Record running state
        self._state = AgentState.RUNNING
        self._store.set_state("agent_state", AgentState.RUNNING.value)
        self._store.set_state("agent_id", self._config.agent_id)
        self._store.set_state("customer_id", self._config.customer_id)
        self._store.set_state("start_time", str(self._start_time))

        logger.info(
            "Medusa Agent started (agent_id=%s, customer_id=%s)",
            self._config.agent_id,
            self._config.customer_id,
        )

        try:
            # Run all subtasks concurrently
            tasks = self._build_tasks()
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            await self._cleanup()

    def _build_tasks(self) -> list[asyncio.Task]:
        """Build the list of concurrent daemon subtasks."""
        tasks: list[asyncio.Task] = []

        if self._config.config_watch_enabled:
            tasks.append(
                asyncio.create_task(
                    self._run_loop(
                        "config_watcher",
                        self._config.config_watch_interval_seconds,
                        self._tick_config_watcher,
                    )
                )
            )

        if self._config.telemetry_enabled:
            tasks.append(
                asyncio.create_task(
                    self._run_loop(
                        "telemetry",
                        self._config.telemetry_interval_seconds,
                        self._tick_telemetry,
                    )
                )
            )

        if self._config.policy_sync_enabled:
            tasks.append(
                asyncio.create_task(
                    self._run_loop(
                        "policy_sync",
                        self._config.policy_sync_interval_seconds,
                        self._tick_policy_sync,
                    )
                )
            )

        tasks.append(
            asyncio.create_task(
                self._run_loop(
                    "health_check",
                    self._config.health_check_interval_seconds,
                    self._tick_health_check,
                )
            )
        )

        if self._config.config_monitor_enabled:
            tasks.append(
                asyncio.create_task(
                    self._run_loop(
                        "config_monitor",
                        self._config.config_monitor_interval_seconds,
                        self._tick_config_monitor,
                    )
                )
            )

        return tasks

    async def _run_loop(
        self,
        name: str,
        interval: int,
        tick_fn: callable,
    ) -> None:
        """Generic loop: call tick_fn every `interval` seconds until shutdown."""
        logger.debug("Starting %s loop (interval=%ds)", name, interval)
        while not self._shutdown_event.is_set():
            try:
                await tick_fn()
            except Exception:
                logger.exception("Error in %s tick", name)

            # Wait with interruptible sleep
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=interval,
                )
                break  # Shutdown requested
            except TimeoutError:
                continue  # Normal timeout, run next tick

    # ── Tick functions (called periodically) ─────────────────────────

    async def _tick_config_watcher(self) -> None:
        """Check for new MCP server configs and auto-proxy them."""
        # Delegated to ConfigWatcher (Phase 2)
        from medusa.agent.config_watcher import ConfigWatcher

        watcher = ConfigWatcher(self._store)
        watcher.check_and_install()

    async def _tick_telemetry(self) -> None:
        """Upload pending events to the dashboard."""
        # Delegated to TelemetryManager (Phase 3)
        from medusa.agent.telemetry import TelemetryManager

        manager = TelemetryManager(self._config, self._store)
        await manager.upload_batch()

    async def _tick_policy_sync(self) -> None:
        """Fetch latest policy from the dashboard."""
        # Delegated to PolicySyncManager (Phase 4)
        from medusa.agent.policy_sync import PolicySyncManager

        manager = PolicySyncManager(self._config)
        await manager.sync()

    async def _tick_health_check(self) -> None:
        """Check proxy process liveness."""
        # Delegated to HealthMonitor (Phase 5)
        from medusa.agent.health import HealthMonitor

        monitor = HealthMonitor(self._store)
        monitor.check_all()

    async def _tick_config_monitor(self) -> None:
        """Run config drift detection, security checks, and posture scoring."""
        from medusa.agent.config_monitor import (
            ConfigDriftDetector,
            ConfigSecurityChecker,
            PostureScorer,
            findings_to_events,
            posture_to_event,
        )

        # 1. Drift detection
        drift = ConfigDriftDetector(self._store)
        drift_events = drift.detect_drift()
        for event in drift_events:
            event.agent_id = self._config.agent_id
            event.customer_id = self._config.customer_id
            self._store.insert_event(event)
        if drift_events:
            drift.update_baseline()
            logger.info("Config drift detected: %d change(s)", len(drift_events))

        # 2. Security checks
        checker = ConfigSecurityChecker()
        findings = checker.check_all_configs()
        finding_events = findings_to_events(findings)
        for event in finding_events:
            event.agent_id = self._config.agent_id
            event.customer_id = self._config.customer_id
            self._store.insert_event(event)
        if findings:
            logger.info("Config security: %d finding(s)", len(findings))

        # 3. Posture scoring
        scorer = PostureScorer()
        posture = scorer.calculate(findings=findings)
        posture_event = posture_to_event(posture)
        posture_event.agent_id = self._config.agent_id
        posture_event.customer_id = self._config.customer_id
        self._store.insert_event(posture_event)
        logger.debug("Posture: %s (%.0f%% coverage)", posture.posture, posture.gateway_coverage_pct)

    # ── Shutdown ─────────────────────────────────────────────────────

    def _request_shutdown(self) -> None:
        """Signal the daemon to shut down gracefully."""
        logger.info("Shutdown requested")
        self._shutdown_event.set()

    async def _cleanup(self) -> None:
        """Clean up resources on shutdown."""
        self._state = AgentState.STOPPING
        logger.info("Cleaning up...")

        self._store.set_state("agent_state", AgentState.STOPPED.value)
        remove_pid_file()

        self._state = AgentState.STOPPED
        logger.info("Medusa Agent stopped (uptime=%.1fs)", self.uptime)
