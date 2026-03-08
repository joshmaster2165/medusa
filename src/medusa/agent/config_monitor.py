"""Configuration monitoring for MCP client configs.

Integrated into the agent→gateway flow. Provides:
- **Drift detection**: snapshots configs and detects changes
- **Security checks**: 10 lightweight rules (CFG001–CFG010)
- **Posture scoring**: GREEN / YELLOW / RED compliance rating
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from medusa.agent.models import TelemetryEvent
from medusa.agent.store import AgentStore
from medusa.connectors.mcp_clients import (
    CLIENT_DISPLAY_NAMES,
    CONFIG_PATHS,
    _expand_path,
    _extract_servers,
    _get_platform_key,
    _parse_config_file,
)
from medusa.gateway.config_rewriter import GATEWAY_MARKER
from medusa.utils.patterns.credentials import SECRET_PATTERNS

logger = logging.getLogger(__name__)

# ── Data classes ──────────────────────────────────────────────────────


@dataclass
class ConfigFinding:
    """A single config security finding."""

    rule_id: str  # "CFG001"
    severity: str  # "critical" | "high" | "medium" | "low"
    client_name: str  # "Claude Desktop"
    server_name: str  # "filesystem-server"
    description: str  # Human-readable
    evidence: str  # The offending config snippet


@dataclass
class PostureReport:
    """Compliance posture snapshot."""

    total_servers: int = 0
    proxied_servers: int = 0
    gateway_coverage_pct: float = 0.0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    dlp_enabled: bool = False
    rate_limiting_configured: bool = False
    posture: str = "RED"  # "GREEN" | "YELLOW" | "RED"
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


# ── Drift Detection ──────────────────────────────────────────────────

BASELINE_STATE_KEY = "config_baseline"


class ConfigDriftDetector:
    """Detects changes in MCP client configurations.

    Captures a JSON snapshot of all configs as a baseline and
    compares against current state to detect drift events.
    """

    def __init__(self, store: AgentStore) -> None:
        self._store = store
        self._platform_key = _get_platform_key()

    def _snapshot_all_configs(self) -> dict[str, dict[str, Any]]:
        """Snapshot all MCP client configs into a dict.

        Returns: {client_name: {server_name: entry_hash, ...}, ...}
        """
        snapshot: dict[str, dict[str, Any]] = {}
        for client_name, paths in CONFIG_PATHS.items():
            path_str = paths.get(self._platform_key)
            if not path_str:
                continue
            config_path = _expand_path(path_str)
            if not config_path.exists():
                continue
            data = _parse_config_file(config_path)
            if not data:
                continue
            servers = _extract_servers(data)
            if servers:
                snapshot[client_name] = {
                    name: _hash_entry(entry) for name, entry in servers.items()
                }
        return snapshot

    def capture_baseline(self) -> dict[str, dict[str, Any]]:
        """Snapshot current configs and store as baseline."""
        snapshot = self._snapshot_all_configs()
        self._store.set_state(BASELINE_STATE_KEY, json.dumps(snapshot))
        logger.debug("Config baseline captured: %d clients", len(snapshot))
        return snapshot

    def _load_baseline(self) -> dict[str, dict[str, Any]]:
        """Load the stored baseline."""
        raw = self._store.get_state(BASELINE_STATE_KEY, "")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def detect_drift(self) -> list[TelemetryEvent]:
        """Compare current configs vs baseline, emit drift events."""
        baseline = self._load_baseline()
        if not baseline:
            # No baseline yet — capture one and return no drift
            self.capture_baseline()
            return []

        current = self._snapshot_all_configs()
        events: list[TelemetryEvent] = []

        # Check all clients in current + baseline
        all_clients = set(baseline.keys()) | set(current.keys())
        for client in all_clients:
            base_servers = baseline.get(client, {})
            curr_servers = current.get(client, {})

            # Detect added servers
            for name in set(curr_servers) - set(base_servers):
                events.append(
                    _drift_event(
                        client_name=client,
                        server_name=name,
                        drift_type="server_added",
                        description=f"New server '{name}' added to {_display(client)}",
                    )
                )

            # Detect removed servers
            for name in set(base_servers) - set(curr_servers):
                events.append(
                    _drift_event(
                        client_name=client,
                        server_name=name,
                        drift_type="server_removed",
                        description=f"Server '{name}' removed from {_display(client)}",
                    )
                )

            # Detect changed servers
            for name in set(base_servers) & set(curr_servers):
                if base_servers[name] != curr_servers[name]:
                    events.append(
                        _drift_event(
                            client_name=client,
                            server_name=name,
                            drift_type="server_changed",
                            description=f"Server '{name}' config changed in {_display(client)}",
                        )
                    )

        return events

    def update_baseline(self) -> None:
        """Update baseline to current state (after drift is acknowledged)."""
        self.capture_baseline()


# ── Security Checker (10 rules) ──────────────────────────────────────

# Unsafe pipe patterns
_PIPE_CMD_RE = re.compile(
    r"(curl|wget|fetch)\b.*\|\s*(sh|bash|zsh|python|node|ruby|perl)\b",
    re.IGNORECASE,
)
_EVAL_CMD_RE = re.compile(r"\b(eval|exec)\b", re.IGNORECASE)
_DYNAMIC_CMD_RE = re.compile(r"(\$\(|`[^`]+`|\$\{)", re.IGNORECASE)
_BROAD_PATH_RE = re.compile(r"^[/~]$|^[A-Z]:\\$|^/\s|^~\s")


class ConfigSecurityChecker:
    """10 lightweight security rules for MCP client configs.

    Each rule inspects raw config data — no server connectivity
    needed, runs in <1ms total.
    """

    def __init__(self) -> None:
        self._platform_key = _get_platform_key()

    def check_all_configs(self) -> list[ConfigFinding]:
        """Run all 10 rules against all discoverable configs."""
        findings: list[ConfigFinding] = []

        for client_name, paths in CONFIG_PATHS.items():
            path_str = paths.get(self._platform_key)
            if not path_str:
                continue
            config_path = _expand_path(path_str)
            if not config_path.exists():
                continue
            data = _parse_config_file(config_path)
            if not data:
                continue
            servers = _extract_servers(data)
            for server_name, entry in servers.items():
                findings.extend(self._check_server(client_name, server_name, entry))

        return findings

    def _check_server(
        self,
        client_name: str,
        server_name: str,
        entry: dict[str, Any],
    ) -> list[ConfigFinding]:
        """Run all rules against a single server entry."""
        findings: list[ConfigFinding] = []
        display = _display(client_name)

        command = entry.get("command", "")
        args = entry.get("args", [])
        env = entry.get("env", {})
        cmd_line = f"{command} {' '.join(str(a) for a in args)}"

        # CFG001: Unsafe pipe command
        if _PIPE_CMD_RE.search(cmd_line):
            findings.append(
                ConfigFinding(
                    rule_id="CFG001",
                    severity="critical",
                    client_name=display,
                    server_name=server_name,
                    description="Unsafe pipe command (curl|sh pattern) in server config",
                    evidence=cmd_line[:120],
                )
            )

        # CFG002: Eval/exec in command
        if command and _EVAL_CMD_RE.search(command):
            findings.append(
                ConfigFinding(
                    rule_id="CFG002",
                    severity="high",
                    client_name=display,
                    server_name=server_name,
                    description="eval/exec used in server command",
                    evidence=command[:80],
                )
            )

        # CFG003: Secrets in env vars
        if env and isinstance(env, dict):
            for env_key, env_val in env.items():
                if not isinstance(env_val, str):
                    continue
                for _pat_name, pattern in SECRET_PATTERNS:
                    if pattern.search(env_val):
                        findings.append(
                            ConfigFinding(
                                rule_id="CFG003",
                                severity="high",
                                client_name=display,
                                server_name=server_name,
                                description=f"Secret detected in env var '{env_key}'",
                                evidence=f"{env_key}={env_val[:8]}***",
                            )
                        )
                        break  # one finding per env var

        # CFG004: Missing gateway proxy
        if "command" in entry and not entry.get(GATEWAY_MARKER):
            findings.append(
                ConfigFinding(
                    rule_id="CFG004",
                    severity="medium",
                    client_name=display,
                    server_name=server_name,
                    description="Server not routed through Medusa gateway proxy",
                    evidence=f"command: {command}",
                )
            )

        # CFG005: Unknown server source
        if command and "npx" in command.lower():
            # Check for well-known npm scope vs unknown packages
            for arg in args:
                if isinstance(arg, str) and arg.startswith("-"):
                    continue
                if isinstance(arg, str) and not arg.startswith("@"):
                    # Non-scoped npm package — flag as unknown
                    findings.append(
                        ConfigFinding(
                            rule_id="CFG005",
                            severity="medium",
                            client_name=display,
                            server_name=server_name,
                            description="Non-scoped npm package used as MCP server",
                            evidence=f"package: {arg}",
                        )
                    )
                    break

        # CFG006: Broad filesystem access
        for arg in args:
            if isinstance(arg, str) and _BROAD_PATH_RE.match(arg):
                findings.append(
                    ConfigFinding(
                        rule_id="CFG006",
                        severity="medium",
                        client_name=display,
                        server_name=server_name,
                        description="Overly broad filesystem path in server args",
                        evidence=f"path: {arg}",
                    )
                )
                break

        # CFG007: Excessive env vars
        if isinstance(env, dict) and len(env) > 10:
            findings.append(
                ConfigFinding(
                    rule_id="CFG007",
                    severity="low",
                    client_name=display,
                    server_name=server_name,
                    description=f"Excessive env vars ({len(env)}) — potential attack surface",
                    evidence=f"{len(env)} env vars configured",
                )
            )

        # CFG008: Dynamic/shell interpolation in command
        if _DYNAMIC_CMD_RE.search(cmd_line):
            findings.append(
                ConfigFinding(
                    rule_id="CFG008",
                    severity="high",
                    client_name=display,
                    server_name=server_name,
                    description="Shell interpolation in server command",
                    evidence=cmd_line[:120],
                )
            )

        # CFG009: Hardcoded credentials in args
        args_str = " ".join(str(a) for a in args)
        for pat_name, pattern in SECRET_PATTERNS:
            if pattern.search(args_str):
                findings.append(
                    ConfigFinding(
                        rule_id="CFG009",
                        severity="critical",
                        client_name=display,
                        server_name=server_name,
                        description=f"Hardcoded credential ({pat_name}) in server args",
                        evidence=args_str[:80] + "***",
                    )
                )
                break  # one finding per server

        # CFG010: Disabled/bypassed gateway
        marker = entry.get(GATEWAY_MARKER)
        if marker:
            orig_cmd = marker.get("original_command", "")
            if command and "medusa" not in command.lower() and orig_cmd:
                findings.append(
                    ConfigFinding(
                        rule_id="CFG010",
                        severity="medium",
                        client_name=display,
                        server_name=server_name,
                        description="Gateway marker present but command bypasses proxy",
                        evidence=f"command: {command} (original: {orig_cmd})",
                    )
                )

        return findings


# ── Posture Scorer ───────────────────────────────────────────────────


class PostureScorer:
    """Calculates a compliance posture score from config state.

    GREEN: 100% gateway coverage, 0 critical/high, DLP enabled
    YELLOW: ≥50% coverage, ≤2 high findings
    RED: <50% coverage OR any critical findings OR DLP disabled
    """

    def __init__(self) -> None:
        self._platform_key = _get_platform_key()

    def calculate(
        self,
        findings: list[ConfigFinding] | None = None,
    ) -> PostureReport:
        """Calculate posture from current config state."""
        # Count servers + gateway coverage
        total = 0
        proxied = 0

        for client_name, paths in CONFIG_PATHS.items():
            path_str = paths.get(self._platform_key)
            if not path_str:
                continue
            config_path = _expand_path(path_str)
            if not config_path.exists():
                continue
            data = _parse_config_file(config_path)
            if not data:
                continue
            servers = _extract_servers(data)
            for _name, entry in servers.items():
                if "command" not in entry:
                    continue  # Skip HTTP/SSE servers
                total += 1
                if entry.get(GATEWAY_MARKER):
                    proxied += 1

        coverage = (proxied / total * 100.0) if total > 0 else 100.0

        # Check DLP and rate limiting from gateway policy
        dlp_enabled = False
        rate_limiting = False
        try:
            from medusa.gateway.policy import load_gateway_policy

            policy = load_gateway_policy()
            dlp_enabled = policy.block_secrets or policy.block_pii
            rate_limiting = policy.max_calls_per_minute > 0
        except Exception:
            pass

        # Count findings by severity
        if findings is None:
            checker = ConfigSecurityChecker()
            findings = checker.check_all_configs()

        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        # Determine posture
        if coverage >= 100 and critical == 0 and high == 0 and dlp_enabled:
            posture = "GREEN"
        elif coverage >= 50 and critical == 0 and high <= 2:
            posture = "YELLOW"
        else:
            posture = "RED"

        return PostureReport(
            total_servers=total,
            proxied_servers=proxied,
            gateway_coverage_pct=round(coverage, 1),
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            dlp_enabled=dlp_enabled,
            rate_limiting_configured=rate_limiting,
            posture=posture,
        )


# ── Helpers ──────────────────────────────────────────────────────────


def _hash_entry(entry: dict[str, Any]) -> str:
    """Hash a server config entry for drift comparison."""
    # Exclude volatile fields (timestamps in gateway marker)
    stable = {k: v for k, v in entry.items() if k != GATEWAY_MARKER or not isinstance(v, dict)}
    if GATEWAY_MARKER in entry and isinstance(entry[GATEWAY_MARKER], dict):
        marker = {k: v for k, v in entry[GATEWAY_MARKER].items() if k != "installed_at"}
        stable[GATEWAY_MARKER] = marker

    raw = json.dumps(stable, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _display(client_name: str) -> str:
    """Get display name for a client."""
    return CLIENT_DISPLAY_NAMES.get(client_name, client_name)


def _drift_event(
    client_name: str,
    server_name: str,
    drift_type: str,
    description: str,
) -> TelemetryEvent:
    """Create a telemetry event for a config drift detection."""
    return TelemetryEvent(
        direction="config",
        message_type="config_drift",
        rule_name=drift_type,
        server_name=server_name,
        reason=description,
        metadata={
            "client_name": client_name,
            "drift_type": drift_type,
        },
    )


def findings_to_events(findings: list[ConfigFinding]) -> list[TelemetryEvent]:
    """Convert config findings to telemetry events."""
    events: list[TelemetryEvent] = []
    for f in findings:
        events.append(
            TelemetryEvent(
                direction="config",
                message_type="config_finding",
                rule_name=f.rule_id,
                server_name=f.server_name,
                reason=f.description,
                verdict=f.severity,
                metadata={
                    "client_name": f.client_name,
                    "severity": f.severity,
                    "evidence": f.evidence,
                },
            )
        )
    return events


def posture_to_event(report: PostureReport) -> TelemetryEvent:
    """Convert a posture report to a telemetry event."""
    return TelemetryEvent(
        direction="config",
        message_type="posture_update",
        rule_name=report.posture,
        reason=f"Posture: {report.posture} ({report.gateway_coverage_pct}% coverage)",
        metadata={
            "total_servers": report.total_servers,
            "proxied_servers": report.proxied_servers,
            "gateway_coverage_pct": report.gateway_coverage_pct,
            "critical_findings": report.critical_findings,
            "high_findings": report.high_findings,
            "medium_findings": report.medium_findings,
            "low_findings": report.low_findings,
            "dlp_enabled": report.dlp_enabled,
            "rate_limiting_configured": report.rate_limiting_configured,
            "posture": report.posture,
        },
    )
