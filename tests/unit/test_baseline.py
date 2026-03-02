"""Tests for baseline management (fingerprinting, save/load, filtering)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from medusa.core.baseline import (
    Baseline,
    BaselineEntry,
    filter_new_findings,
    fingerprint_finding,
    generate_baseline,
    load_baseline,
    save_baseline,
    suppress_finding,
    unsuppress_finding,
)
from medusa.core.models import Finding, ScanResult, Severity, Status


def _make_finding(
    check_id: str = "tp001",
    server_name: str = "test-server",
    resource_type: str = "tool",
    resource_name: str = "execute",
    severity: Severity = Severity.HIGH,
    status: Status = Status.FAIL,
    check_title: str = "Test Finding",
) -> Finding:
    """Create a test finding."""
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


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    """Create a test scan result."""
    if findings is None:
        findings = [_make_finding()]
    return ScanResult(
        scan_id="test-001",
        timestamp=datetime.now(UTC),
        medusa_version="0.1.0",
        scan_duration_seconds=1.0,
        servers_scanned=1,
        total_findings=sum(1 for f in findings if f.status == Status.FAIL),
        findings=findings,
        server_scores=[],
        aggregate_score=8.0,
        aggregate_grade="B",
    )


class TestFingerprint:
    """Tests for fingerprint generation."""

    def test_fingerprint_is_deterministic(self):
        f1 = _make_finding()
        f2 = _make_finding()
        assert fingerprint_finding(f1) == fingerprint_finding(f2)

    def test_different_check_ids_produce_different_fingerprints(self):
        f1 = _make_finding(check_id="tp001")
        f2 = _make_finding(check_id="tp002")
        assert fingerprint_finding(f1) != fingerprint_finding(f2)

    def test_different_servers_produce_different_fingerprints(self):
        f1 = _make_finding(server_name="server-a")
        f2 = _make_finding(server_name="server-b")
        assert fingerprint_finding(f1) != fingerprint_finding(f2)

    def test_different_resources_produce_different_fingerprints(self):
        f1 = _make_finding(resource_name="tool_a")
        f2 = _make_finding(resource_name="tool_b")
        assert fingerprint_finding(f1) != fingerprint_finding(f2)

    def test_fingerprint_is_16_chars(self):
        fp = fingerprint_finding(_make_finding())
        assert len(fp) == 16
        assert fp.isalnum()


class TestGenerateBaseline:
    """Tests for baseline generation from scan results."""

    def test_generates_from_fail_findings(self):
        findings = [
            _make_finding(check_id="tp001", status=Status.FAIL),
            _make_finding(check_id="tp002", status=Status.PASS),
            _make_finding(check_id="tp003", status=Status.FAIL),
        ]
        result = _make_result(findings)
        baseline = generate_baseline(result)

        assert len(baseline.entries) == 2
        check_ids = {e.check_id for e in baseline.entries}
        assert check_ids == {"tp001", "tp003"}

    def test_skips_pass_findings(self):
        findings = [
            _make_finding(check_id="tp001", status=Status.PASS),
        ]
        result = _make_result(findings)
        baseline = generate_baseline(result)
        assert len(baseline.entries) == 0

    def test_deduplicates_findings(self):
        findings = [
            _make_finding(check_id="tp001"),
            _make_finding(check_id="tp001"),  # same fingerprint
        ]
        result = _make_result(findings)
        baseline = generate_baseline(result)
        assert len(baseline.entries) == 1

    def test_stores_metadata(self):
        result = _make_result()
        baseline = generate_baseline(result)
        assert baseline.medusa_version == "0.1.0"
        assert baseline.scan_id == "test-001"
        assert baseline.version == 1


class TestSaveLoad:
    """Tests for save/load roundtrip."""

    def test_roundtrip(self, tmp_path: Path):
        baseline = Baseline(
            medusa_version="0.1.0",
            scan_id="abc",
            entries=[
                BaselineEntry(
                    fingerprint="abc123def456abcd",
                    check_id="tp001",
                    server_name="test",
                    resource_name="tool",
                    severity="high",
                    check_title="Test",
                ),
            ],
        )
        path = tmp_path / "baseline.json"
        save_baseline(baseline, path)
        loaded = load_baseline(path)

        assert len(loaded.entries) == 1
        assert loaded.entries[0].fingerprint == "abc123def456abcd"
        assert loaded.entries[0].check_id == "tp001"
        assert loaded.medusa_version == "0.1.0"

    def test_load_nonexistent_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_baseline(tmp_path / "nonexistent.json")

    def test_load_malformed_raises(self, tmp_path: Path):
        path = tmp_path / "bad.json"
        path.write_text("not json {{{")
        with pytest.raises(ValueError, match="Malformed baseline"):
            load_baseline(path)

    def test_saves_creates_parent_dirs(self, tmp_path: Path):
        path = tmp_path / "deep" / "nested" / "baseline.json"
        baseline = Baseline()
        save_baseline(baseline, path)
        assert path.exists()


class TestFilterNewFindings:
    """Tests for baseline filtering."""

    def test_identifies_new_findings(self):
        old_finding = _make_finding(check_id="tp001")
        new_finding = _make_finding(check_id="tp002")

        result = _make_result([old_finding, new_finding])
        baseline = generate_baseline(
            _make_result([old_finding])
        )

        new, baselined, resolved = filter_new_findings(result, baseline)

        fail_new = [f for f in new if f.status == Status.FAIL]
        assert len(fail_new) == 1
        assert fail_new[0].check_id == "tp002"
        assert len(baselined) == 1
        assert baselined[0].check_id == "tp001"

    def test_identifies_resolved_findings(self):
        old_finding = _make_finding(check_id="tp001")
        result = _make_result([])  # No findings in current scan

        baseline = generate_baseline(
            _make_result([old_finding])
        )

        new, baselined, resolved = filter_new_findings(result, baseline)
        assert len(resolved) == 1

    def test_pass_findings_pass_through(self):
        pass_finding = _make_finding(check_id="tp001", status=Status.PASS)
        result = _make_result([pass_finding])
        baseline = Baseline()

        new, baselined, resolved = filter_new_findings(result, baseline)
        assert len(new) == 1
        assert new[0].status == Status.PASS

    def test_empty_baseline_all_new(self):
        findings = [
            _make_finding(check_id="tp001"),
            _make_finding(check_id="tp002"),
        ]
        result = _make_result(findings)
        baseline = Baseline()

        new, baselined, resolved = filter_new_findings(result, baseline)
        fail_new = [f for f in new if f.status == Status.FAIL]
        assert len(fail_new) == 2
        assert len(baselined) == 0


class TestSuppression:
    """Tests for finding suppression."""

    def test_suppress_finding(self):
        baseline = Baseline(
            entries=[
                BaselineEntry(
                    fingerprint="abc123",
                    check_id="tp001",
                    server_name="test",
                    resource_name="tool",
                    severity="high",
                    check_title="Test",
                ),
            ]
        )
        assert suppress_finding(baseline, "abc123", "accepted risk")
        assert baseline.entries[0].suppressed is True
        assert baseline.entries[0].suppression_reason == "accepted risk"

    def test_suppress_nonexistent_returns_false(self):
        baseline = Baseline()
        assert suppress_finding(baseline, "missing", "reason") is False

    def test_unsuppress_finding(self):
        baseline = Baseline(
            entries=[
                BaselineEntry(
                    fingerprint="abc123",
                    check_id="tp001",
                    server_name="test",
                    resource_name="tool",
                    severity="high",
                    check_title="Test",
                    suppressed=True,
                    suppression_reason="old reason",
                ),
            ]
        )
        assert unsuppress_finding(baseline, "abc123")
        assert baseline.entries[0].suppressed is False
        assert baseline.entries[0].suppression_reason is None

    def test_unsuppress_nonexistent_returns_false(self):
        baseline = Baseline()
        assert unsuppress_finding(baseline, "missing") is False

    def test_suppressed_findings_not_counted_as_resolved(self):
        """Suppressed entries should not appear as 'resolved'."""
        finding = _make_finding(check_id="tp001")
        fp = fingerprint_finding(finding)

        baseline = Baseline(
            entries=[
                BaselineEntry(
                    fingerprint=fp,
                    check_id="tp001",
                    server_name="test-server",
                    resource_name="execute",
                    severity="high",
                    check_title="Test",
                    suppressed=True,
                    suppression_reason="accepted",
                ),
            ]
        )

        # Scan with no findings
        result = _make_result([])
        _new, _baselined, resolved = filter_new_findings(result, baseline)
        assert len(resolved) == 0
