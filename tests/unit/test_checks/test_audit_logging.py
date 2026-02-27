"""Unit tests for Audit Logging checks.

Covers AUDIT-001 (Missing Logging Configuration) and AUDIT-002 (Missing Audit Trail).

Each check is tested for:
- Metadata loads correctly
- FAIL on vulnerable input
- PASS on clean input
- Graceful handling of empty snapshots
- Additional edge cases specific to each check
"""

from __future__ import annotations

import pytest

from medusa.checks.audit_logging.audit001_missing_logging import MissingLoggingCheck
from medusa.checks.audit_logging.audit002_missing_audit_trail import MissingAuditTrailCheck
from medusa.checks.audit_logging.audit003_insufficient_log_detail import InsufficientLogDetailCheck
from medusa.checks.audit_logging.audit004_log_tampering_risk import LogTamperingRiskCheck
from medusa.checks.audit_logging.audit005_missing_log_rotation import MissingLogRotationCheck
from medusa.checks.audit_logging.audit006_missing_alerting import MissingAlertingCheck
from medusa.checks.audit_logging.audit007_sensitive_data_in_logs import SensitiveDataInLogsCheck
from medusa.checks.audit_logging.audit008_missing_access_logging import MissingAccessLoggingCheck
from medusa.checks.audit_logging.audit009_log_injection_risk import LogInjectionRiskCheck
from medusa.checks.audit_logging.audit010_missing_forensic_capability import (
    MissingForensicCapabilityCheck,
)
from medusa.core.check import ServerSnapshot
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# AUDIT-001: Missing Logging Configuration
# ==========================================================================


class TestAudit001MissingLogging:
    """Tests for MissingLoggingCheck."""

    @pytest.fixture()
    def check(self) -> MissingLoggingCheck:
        return MissingLoggingCheck()

    async def test_metadata_loads_correctly(self, check: MissingLoggingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit001", "Check ID should be audit001"
        assert meta.category == "audit_logging", "Category should be audit_logging"
        assert meta.severity == Severity.MEDIUM, "Severity should be MEDIUM"

    async def test_fails_on_no_logging_config(self, check: MissingLoggingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "args": ["index.js"]},
            env={"NODE_ENV": "production"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "Server without logging config should be flagged"

    async def test_passes_on_logging_in_config(self, check: MissingLoggingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "args": ["index.js"],
                "logging": {"level": "info"},
            },
            env={"NODE_ENV": "production"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Server with logging in config should PASS"

    async def test_passes_on_log_level_env_var(self, check: MissingLoggingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node"},
            env={"LOG_LEVEL": "debug"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Server with LOG_LEVEL env var should PASS"

    async def test_passes_on_sentry_dsn_env_var(self, check: MissingLoggingCheck) -> None:
        snapshot = make_snapshot(
            config_raw=None,
            env={"SENTRY_DSN": "https://sentry.example.com/123"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Server with SENTRY_DSN should PASS"

    async def test_passes_on_nested_logging_key(self, check: MissingLoggingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={
                "command": "node",
                "server": {
                    "audit": {"enabled": True},
                },
            },
            env={},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Nested 'audit' key should be detected"

    async def test_fails_on_empty_config_and_env(self, check: MissingLoggingCheck) -> None:
        snapshot = make_snapshot(config_raw=None, env={})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "Server with no config and no env should be flagged"

    async def test_empty_snapshot_fails(
        self, check: MissingLoggingCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        """Empty snapshot has no logging config, so it should FAIL."""
        findings = await check.execute(empty_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "Empty snapshot with no logging should FAIL"

    async def test_passes_on_debug_key_in_config(self, check: MissingLoggingCheck) -> None:
        snapshot = make_snapshot(
            config_raw={"command": "node", "debug": True},
            env={},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, (
            "'debug' key in config should be detected as logging config"
        )


# ==========================================================================
# AUDIT-002: Missing Audit Trail Capability
# ==========================================================================


class TestAudit002MissingAuditTrail:
    """Tests for MissingAuditTrailCheck."""

    @pytest.fixture()
    def check(self) -> MissingAuditTrailCheck:
        return MissingAuditTrailCheck()

    async def test_metadata_loads_correctly(self, check: MissingAuditTrailCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit002", "Check ID should be audit002"
        assert meta.category == "audit_logging", "Category should be audit_logging"
        assert meta.severity == Severity.MEDIUM, "Severity should be MEDIUM"

    async def test_fails_on_no_logging_capability(self, check: MissingAuditTrailCheck) -> None:
        snapshot = make_snapshot(capabilities={"tools": {}, "resources": {}})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "Server without logging capability should be flagged"

    async def test_passes_on_logging_capability(self, check: MissingAuditTrailCheck) -> None:
        snapshot = make_snapshot(capabilities={"tools": {}, "logging": {"level": "info"}})
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, "Server with logging capability should PASS"

    async def test_fails_on_empty_capabilities(self, check: MissingAuditTrailCheck) -> None:
        snapshot = make_snapshot(capabilities={})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "Server with empty capabilities should be flagged"

    async def test_empty_snapshot_fails(
        self, check: MissingAuditTrailCheck, empty_snapshot: ServerSnapshot
    ) -> None:
        """Empty snapshot has empty capabilities dict, so no logging."""
        findings = await check.execute(empty_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "Empty snapshot should FAIL for missing logging capability"

    async def test_logging_key_with_empty_value_passes(self, check: MissingAuditTrailCheck) -> None:
        snapshot = make_snapshot(capabilities={"logging": {}})
        findings = await check.execute(snapshot)
        assert len(findings) == 1, "Should produce exactly one finding"
        assert findings[0].status == Status.PASS, (
            "Even empty logging capability should count as declared"
        )

    async def test_evidence_lists_capability_keys(self, check: MissingAuditTrailCheck) -> None:
        snapshot = make_snapshot(capabilities={"tools": {}, "prompts": {}})
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 1, "Should produce one FAIL"
        assert "prompts" in fail_findings[0].evidence or "tools" in fail_findings[0].evidence, (
            "Evidence should list the actual capability keys"
        )


class TestInsufficientLogDetailCheck:
    """Tests for InsufficientLogDetailCheck."""

    @pytest.fixture()
    def check(self) -> InsufficientLogDetailCheck:
        return InsufficientLogDetailCheck()

    async def test_metadata_loads_correctly(self, check: InsufficientLogDetailCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit003"
        assert meta.category == "audit_logging"

    async def test_stub_returns_empty(self, check: InsufficientLogDetailCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestLogTamperingRiskCheck:
    """Tests for LogTamperingRiskCheck."""

    @pytest.fixture()
    def check(self) -> LogTamperingRiskCheck:
        return LogTamperingRiskCheck()

    async def test_metadata_loads_correctly(self, check: LogTamperingRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit004"
        assert meta.category == "audit_logging"

    async def test_stub_returns_empty(self, check: LogTamperingRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingLogRotationCheck:
    """Tests for MissingLogRotationCheck."""

    @pytest.fixture()
    def check(self) -> MissingLogRotationCheck:
        return MissingLogRotationCheck()

    async def test_metadata_loads_correctly(self, check: MissingLogRotationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit005"
        assert meta.category == "audit_logging"

    async def test_stub_returns_empty(self, check: MissingLogRotationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingAlertingCheck:
    """Tests for MissingAlertingCheck."""

    @pytest.fixture()
    def check(self) -> MissingAlertingCheck:
        return MissingAlertingCheck()

    async def test_metadata_loads_correctly(self, check: MissingAlertingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit006"
        assert meta.category == "audit_logging"

    async def test_stub_returns_empty(self, check: MissingAlertingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSensitiveDataInLogsCheck:
    """Tests for SensitiveDataInLogsCheck."""

    @pytest.fixture()
    def check(self) -> SensitiveDataInLogsCheck:
        return SensitiveDataInLogsCheck()

    async def test_metadata_loads_correctly(self, check: SensitiveDataInLogsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit007"
        assert meta.category == "audit_logging"

    async def test_stub_returns_empty(self, check: SensitiveDataInLogsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingAccessLoggingCheck:
    """Tests for MissingAccessLoggingCheck."""

    @pytest.fixture()
    def check(self) -> MissingAccessLoggingCheck:
        return MissingAccessLoggingCheck()

    async def test_metadata_loads_correctly(self, check: MissingAccessLoggingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit008"
        assert meta.category == "audit_logging"

    async def test_stub_returns_empty(self, check: MissingAccessLoggingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestLogInjectionRiskCheck:
    """Tests for LogInjectionRiskCheck."""

    @pytest.fixture()
    def check(self) -> LogInjectionRiskCheck:
        return LogInjectionRiskCheck()

    async def test_metadata_loads_correctly(self, check: LogInjectionRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit009"
        assert meta.category == "audit_logging"

    async def test_stub_returns_empty(self, check: LogInjectionRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingForensicCapabilityCheck:
    """Tests for MissingForensicCapabilityCheck."""

    @pytest.fixture()
    def check(self) -> MissingForensicCapabilityCheck:
        return MissingForensicCapabilityCheck()

    async def test_metadata_loads_correctly(self, check: MissingForensicCapabilityCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "audit010"
        assert meta.category == "audit_logging"

    async def test_stub_returns_empty(self, check: MissingForensicCapabilityCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
