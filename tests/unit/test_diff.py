"""Tests for scan result diffing."""

from __future__ import annotations

from datetime import UTC, datetime

from medusa.core.diff import diff_scan_results
from medusa.core.models import (
    Finding,
    ScanResult,
    ServerScore,
    Severity,
    Status,
)


def _make_finding(
    check_id: str = "tp001",
    server_name: str = "test-server",
    resource_type: str = "tool",
    resource_name: str = "execute",
    severity: Severity = Severity.HIGH,
    status: Status = Status.FAIL,
    check_title: str = "Test Finding",
) -> Finding:
    return Finding(
        check_id=check_id,
        check_title=check_title,
        status=status,
        severity=severity,
        server_name=server_name,
        server_transport="stdio",
        resource_type=resource_type,
        resource_name=resource_name,
        status_extended="Test detail",
        remediation="Fix it",
    )


def _make_result(
    scan_id: str = "test-001",
    findings: list[Finding] | None = None,
    server_scores: list[ServerScore] | None = None,
    aggregate_score: float = 8.0,
    aggregate_grade: str = "B",
) -> ScanResult:
    if findings is None:
        findings = []
    if server_scores is None:
        server_scores = []
    return ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now(UTC),
        medusa_version="0.1.0",
        scan_duration_seconds=1.0,
        servers_scanned=1,
        total_findings=sum(1 for f in findings if f.status == Status.FAIL),
        findings=findings,
        server_scores=server_scores,
        aggregate_score=aggregate_score,
        aggregate_grade=aggregate_grade,
    )


class TestDiffScanResults:
    """Tests for scan result diffing."""

    def test_identical_scans_produce_empty_diff(self):
        findings = [_make_finding(check_id="tp001")]
        before = _make_result(scan_id="a", findings=findings)
        after = _make_result(scan_id="b", findings=findings)

        d = diff_scan_results(before, after)
        assert d.total_new == 0
        assert d.total_resolved == 0
        assert d.total_severity_changes == 0

    def test_new_finding_detected(self):
        before = _make_result(scan_id="a", findings=[])
        after = _make_result(
            scan_id="b",
            findings=[_make_finding(check_id="tp001")],
        )

        d = diff_scan_results(before, after)
        assert d.total_new == 1
        assert d.new_findings[0].check_id == "tp001"

    def test_resolved_finding_detected(self):
        before = _make_result(
            scan_id="a",
            findings=[_make_finding(check_id="tp001")],
        )
        after = _make_result(scan_id="b", findings=[])

        d = diff_scan_results(before, after)
        assert d.total_resolved == 1
        assert d.resolved_findings[0].check_id == "tp001"

    def test_severity_change_shows_as_resolved_and_new(self):
        """When severity changes, the fingerprint changes (since severity
        is part of the identity). This means the old finding appears as
        'resolved' and the new one appears as 'new'."""
        before = _make_result(
            scan_id="a",
            findings=[_make_finding(check_id="tp001", severity=Severity.MEDIUM)],
        )
        after = _make_result(
            scan_id="b",
            findings=[_make_finding(check_id="tp001", severity=Severity.CRITICAL)],
        )

        d = diff_scan_results(before, after)
        # Severity is part of the fingerprint, so different severity = different finding
        assert d.total_resolved == 1
        assert d.resolved_findings[0].severity == "medium"
        assert d.total_new == 1
        assert d.new_findings[0].severity == "critical"

    def test_mixed_changes(self):
        before_findings = [
            _make_finding(check_id="tp001"),  # will be resolved
            _make_finding(check_id="tp002"),  # stays
        ]
        after_findings = [
            _make_finding(check_id="tp002"),  # stays
            _make_finding(check_id="tp003"),  # new
        ]

        before = _make_result(scan_id="a", findings=before_findings)
        after = _make_result(scan_id="b", findings=after_findings)

        d = diff_scan_results(before, after)
        assert d.total_new == 1
        assert d.total_resolved == 1
        assert d.new_findings[0].check_id == "tp003"
        assert d.resolved_findings[0].check_id == "tp001"

    def test_pass_findings_are_ignored(self):
        before = _make_result(
            scan_id="a",
            findings=[_make_finding(check_id="tp001", status=Status.PASS)],
        )
        after = _make_result(
            scan_id="b",
            findings=[_make_finding(check_id="tp002")],
        )

        d = diff_scan_results(before, after)
        assert d.total_new == 1
        assert d.total_resolved == 0

    def test_server_score_changes(self):
        before_scores = [
            ServerScore(
                server_name="server-a",
                score=8.0,
                grade="B",
                total_checks=10,
                passed=8,
                failed=2,
                critical_findings=0,
                high_findings=1,
                medium_findings=1,
                low_findings=0,
            )
        ]
        after_scores = [
            ServerScore(
                server_name="server-a",
                score=6.0,
                grade="C",
                total_checks=10,
                passed=6,
                failed=4,
                critical_findings=1,
                high_findings=1,
                medium_findings=1,
                low_findings=1,
            )
        ]

        before = _make_result(
            scan_id="a",
            server_scores=before_scores,
            aggregate_score=8.0,
            aggregate_grade="B",
        )
        after = _make_result(
            scan_id="b",
            server_scores=after_scores,
            aggregate_score=6.0,
            aggregate_grade="C",
        )

        d = diff_scan_results(before, after)
        assert len(d.server_score_changes) == 1
        assert d.server_score_changes[0].old_score == 8.0
        assert d.server_score_changes[0].new_score == 6.0
        assert d.server_score_changes[0].score_delta == -2.0

    def test_new_findings_sorted_by_severity(self):
        after_findings = [
            _make_finding(check_id="tp001", severity=Severity.LOW),
            _make_finding(check_id="tp002", severity=Severity.CRITICAL),
            _make_finding(check_id="tp003", severity=Severity.MEDIUM),
        ]

        before = _make_result(scan_id="a", findings=[])
        after = _make_result(scan_id="b", findings=after_findings)

        d = diff_scan_results(before, after)
        severities = [f.severity for f in d.new_findings]
        assert severities == ["critical", "medium", "low"]

    def test_aggregate_score_tracking(self):
        before = _make_result(scan_id="a", aggregate_score=9.0, aggregate_grade="A")
        after = _make_result(scan_id="b", aggregate_score=5.0, aggregate_grade="C")

        d = diff_scan_results(before, after)
        assert d.aggregate_score_before == 9.0
        assert d.aggregate_score_after == 5.0
        assert d.aggregate_grade_before == "A"
        assert d.aggregate_grade_after == "C"

    def test_diff_serializes_to_json(self):
        d = diff_scan_results(
            _make_result(scan_id="a"),
            _make_result(scan_id="b"),
        )
        json_str = d.model_dump_json()
        assert "before_scan_id" in json_str
        assert "after_scan_id" in json_str
