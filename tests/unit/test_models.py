"""Tests for medusa.core.models - core data models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from medusa.core.models import (
    CheckMetadata,
    Finding,
    ScanResult,
    ServerScore,
    Severity,
    Status,
)

# ── Severity enum ────────────────────────────────────────────────────────────


class TestSeverityEnum:
    def test_critical_value(self):
        assert Severity.CRITICAL.value == "critical"

    def test_high_value(self):
        assert Severity.HIGH.value == "high"

    def test_medium_value(self):
        assert Severity.MEDIUM.value == "medium"

    def test_low_value(self):
        assert Severity.LOW.value == "low"

    def test_informational_value(self):
        assert Severity.INFORMATIONAL.value == "informational"

    def test_all_values(self):
        expected = {"critical", "high", "medium", "low", "informational"}
        actual = {s.value for s in Severity}
        assert actual == expected


# ── Status enum ──────────────────────────────────────────────────────────────


class TestStatusEnum:
    def test_pass_value(self):
        assert Status.PASS.value == "pass"

    def test_fail_value(self):
        assert Status.FAIL.value == "fail"

    def test_error_value(self):
        assert Status.ERROR.value == "error"

    def test_skipped_value(self):
        assert Status.SKIPPED.value == "skipped"

    def test_all_values(self):
        expected = {"pass", "fail", "error", "skipped"}
        actual = {s.value for s in Status}
        assert actual == expected


# ── CheckMetadata ────────────────────────────────────────────────────────────


class TestCheckMetadata:
    def test_create_with_required_fields(self):
        meta = CheckMetadata(
            check_id="tp001",
            title="Hidden Instructions in Tool Descriptions",
            category="tool_poisoning",
            severity=Severity.CRITICAL,
            description="Detects hidden instructions",
            risk_explanation="May trick the LLM",
            remediation="Remove hidden tags",
        )
        assert meta.check_id == "tp001"
        assert meta.title == "Hidden Instructions in Tool Descriptions"
        assert meta.category == "tool_poisoning"
        assert meta.severity == Severity.CRITICAL
        assert meta.description == "Detects hidden instructions"
        assert meta.risk_explanation == "May trick the LLM"
        assert meta.remediation == "Remove hidden tags"

    def test_optional_fields_default_to_empty_lists(self):
        meta = CheckMetadata(
            check_id="tp001",
            title="Test",
            category="test",
            severity=Severity.LOW,
            description="desc",
            risk_explanation="risk",
            remediation="fix",
        )
        assert meta.references == []
        assert meta.owasp_mcp == []
        assert meta.tags == []

    def test_create_with_all_fields(self):
        meta = CheckMetadata(
            check_id="tp001",
            title="Test",
            category="test",
            severity=Severity.HIGH,
            description="desc",
            risk_explanation="risk",
            remediation="fix",
            references=["https://example.com"],
            owasp_mcp=["MCP03:2025"],
            tags=["injection"],
        )
        assert meta.references == ["https://example.com"]
        assert meta.owasp_mcp == ["MCP03:2025"]
        assert meta.tags == ["injection"]


# ── Finding ──────────────────────────────────────────────────────────────────


class TestFinding:
    def test_create_finding(self):
        finding = Finding(
            check_id="tp001",
            check_title="Test Check",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            server_name="test-server",
            server_transport="stdio",
            resource_type="tool",
            resource_name="exec_command",
            status_extended="Hidden instruction detected",
            remediation="Remove it",
        )
        assert finding.check_id == "tp001"
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL
        assert finding.server_name == "test-server"

    def test_finding_has_auto_timestamp(self):
        before = datetime.now(UTC)
        finding = Finding(
            check_id="tp001",
            check_title="Test Check",
            status=Status.PASS,
            severity=Severity.LOW,
            server_name="test-server",
            server_transport="stdio",
            resource_type="tool",
            resource_name="read_file",
            status_extended="No issues",
            remediation="N/A",
        )
        after = datetime.now(UTC)
        assert before <= finding.timestamp <= after

    def test_finding_evidence_default_none(self):
        finding = Finding(
            check_id="tp001",
            check_title="Test",
            status=Status.PASS,
            severity=Severity.LOW,
            server_name="s",
            server_transport="stdio",
            resource_type="tool",
            resource_name="t",
            status_extended="ok",
            remediation="none",
        )
        assert finding.evidence is None

    def test_finding_owasp_mcp_default_empty(self):
        finding = Finding(
            check_id="tp001",
            check_title="Test",
            status=Status.PASS,
            severity=Severity.LOW,
            server_name="s",
            server_transport="stdio",
            resource_type="tool",
            resource_name="t",
            status_extended="ok",
            remediation="none",
        )
        assert finding.owasp_mcp == []


# ── ServerScore ──────────────────────────────────────────────────────────────


class TestServerScore:
    def test_create_server_score(self):
        score = ServerScore(
            server_name="test-server",
            score=8.5,
            grade="B",
            total_checks=10,
            passed=8,
            failed=2,
            critical_findings=0,
            high_findings=1,
            medium_findings=1,
            low_findings=0,
        )
        assert score.server_name == "test-server"
        assert score.score == 8.5
        assert score.grade == "B"
        assert score.total_checks == 10
        assert score.passed == 8
        assert score.failed == 2
        assert score.critical_findings == 0
        assert score.high_findings == 1


# ── ScanResult ───────────────────────────────────────────────────────────────


class TestScanResult:
    def test_create_scan_result(self):
        finding = Finding(
            check_id="tp001",
            check_title="Test",
            status=Status.PASS,
            severity=Severity.LOW,
            server_name="test-server",
            server_transport="stdio",
            resource_type="tool",
            resource_name="t",
            status_extended="ok",
            remediation="none",
        )
        server_score = ServerScore(
            server_name="test-server",
            score=9.0,
            grade="A",
            total_checks=1,
            passed=1,
            failed=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        )
        result = ScanResult(
            scan_id="scan-001",
            timestamp=datetime.now(UTC),
            medusa_version="0.1.0",
            scan_duration_seconds=2.5,
            servers_scanned=1,
            total_findings=1,
            findings=[finding],
            server_scores=[server_score],
            aggregate_score=9.0,
            aggregate_grade="A",
        )
        assert result.scan_id == "scan-001"
        assert result.medusa_version == "0.1.0"
        assert result.servers_scanned == 1
        assert result.total_findings == 1
        assert len(result.findings) == 1
        assert len(result.server_scores) == 1
        assert result.aggregate_score == 9.0
        assert result.aggregate_grade == "A"
        assert result.compliance_results == {}


# ── Pydantic validation ─────────────────────────────────────────────────────


class TestPydanticValidation:
    def test_finding_missing_required_field_raises_error(self):
        with pytest.raises(ValidationError):
            Finding(
                check_id="tp001",
                # missing check_title and other required fields
            )

    def test_invalid_severity_raises_error(self):
        with pytest.raises(ValidationError):
            Finding(
                check_id="tp001",
                check_title="Test",
                status=Status.PASS,
                severity="invalid_severity",
                server_name="s",
                server_transport="stdio",
                resource_type="tool",
                resource_name="t",
                status_extended="ok",
                remediation="none",
            )

    def test_invalid_status_raises_error(self):
        with pytest.raises(ValidationError):
            Finding(
                check_id="tp001",
                check_title="Test",
                status="invalid_status",
                severity=Severity.LOW,
                server_name="s",
                server_transport="stdio",
                resource_type="tool",
                resource_name="t",
                status_extended="ok",
                remediation="none",
            )
