"""Tests for medusa.compliance.framework - compliance framework loading and evaluation."""

import pytest

from medusa.compliance.framework import evaluate_compliance, load_framework
from medusa.core.models import Finding, Severity, Status


def _make_finding(
    check_id: str = "tp001",
    status: Status = Status.PASS,
    severity: Severity = Severity.CRITICAL,
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    return Finding(
        check_id=check_id,
        check_title="Test",
        status=status,
        severity=severity,
        server_name="test-server",
        server_transport="stdio",
        resource_type="server",
        resource_name="test-server",
        status_extended="Test finding",
        remediation="Fix it",
    )


# ── load_framework ───────────────────────────────────────────────────────────


class TestLoadFramework:
    def test_load_owasp_mcp_top10(self):
        fw = load_framework("owasp_mcp_top10")
        assert fw is not None
        assert fw.name is not None
        assert len(fw.name) > 0

    def test_load_nonexistent_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_framework("nonexistent")

    def test_loaded_framework_has_name(self):
        fw = load_framework("owasp_mcp_top10")
        assert "OWASP" in fw.name or "MCP" in fw.name or "Top" in fw.name

    def test_loaded_framework_has_version(self):
        fw = load_framework("owasp_mcp_top10")
        assert fw.version is not None
        assert len(fw.version) > 0

    def test_loaded_framework_has_requirements(self):
        fw = load_framework("owasp_mcp_top10")
        assert isinstance(fw.requirements, dict)
        assert len(fw.requirements) > 0

    def test_requirements_have_titles_and_checks(self):
        fw = load_framework("owasp_mcp_top10")
        for req_id, req in fw.requirements.items():
            assert req.title is not None
            assert isinstance(req.checks, list)


# ── evaluate_compliance ──────────────────────────────────────────────────────


class TestEvaluateCompliance:
    def test_all_pass_returns_compliant(self):
        fw = load_framework("owasp_mcp_top10")
        # Create PASS findings for all checks in the first requirement
        first_req_id = next(iter(fw.requirements))
        first_req = fw.requirements[first_req_id]

        findings = [_make_finding(check_id=cid, status=Status.PASS) for cid in first_req.checks]
        results = evaluate_compliance(fw, findings)

        assert results[first_req_id]["status"] == "compliant"
        assert results[first_req_id]["checks_passed"] == len(first_req.checks)
        assert results[first_req_id]["checks_failed"] == 0

    def test_fail_findings_returns_non_compliant(self):
        fw = load_framework("owasp_mcp_top10")
        first_req_id = next(iter(fw.requirements))
        first_req = fw.requirements[first_req_id]

        findings = [_make_finding(check_id=cid, status=Status.FAIL) for cid in first_req.checks]
        results = evaluate_compliance(fw, findings)

        assert results[first_req_id]["status"] == "non_compliant"
        assert results[first_req_id]["checks_failed"] > 0

    def test_empty_checks_returns_not_assessed(self):
        """A requirement with no checks mapped should be not_assessed."""
        from medusa.compliance.framework import ComplianceFramework, FrameworkRequirement

        fw = ComplianceFramework(
            name="Test Framework",
            version="1.0",
            requirements={
                "REQ01": FrameworkRequirement(title="Empty Requirement", checks=[]),
            },
        )
        findings = [_make_finding()]
        results = evaluate_compliance(fw, findings)

        assert results["REQ01"]["status"] == "not_assessed"
        assert results["REQ01"]["checks_total"] == 0

    def test_no_matching_findings_returns_not_assessed(self):
        """When checks exist but no findings match, status should be not_assessed."""
        from medusa.compliance.framework import ComplianceFramework, FrameworkRequirement

        fw = ComplianceFramework(
            name="Test Framework",
            version="1.0",
            requirements={
                "REQ01": FrameworkRequirement(
                    title="Unmatched Requirement",
                    checks=["nonexistent_check_001", "nonexistent_check_002"],
                ),
            },
        )
        findings = [_make_finding(check_id="tp001")]
        results = evaluate_compliance(fw, findings)

        assert results["REQ01"]["status"] == "not_assessed"
        # Verify details show not_run
        for detail in results["REQ01"]["details"]:
            assert detail["status"] == "not_run"

    def test_mixed_pass_and_fail(self):
        """If some checks pass and some fail, status should be non_compliant."""
        from medusa.compliance.framework import ComplianceFramework, FrameworkRequirement

        fw = ComplianceFramework(
            name="Test Framework",
            version="1.0",
            requirements={
                "REQ01": FrameworkRequirement(
                    title="Mixed Requirement",
                    checks=["check_a", "check_b"],
                ),
            },
        )
        findings = [
            _make_finding(check_id="check_a", status=Status.PASS),
            _make_finding(check_id="check_b", status=Status.FAIL),
        ]
        results = evaluate_compliance(fw, findings)

        assert results["REQ01"]["status"] == "non_compliant"
        assert results["REQ01"]["checks_passed"] == 1
        assert results["REQ01"]["checks_failed"] == 1

    def test_empty_findings_list(self):
        fw = load_framework("owasp_mcp_top10")
        results = evaluate_compliance(fw, [])
        # All requirements with checks should be not_assessed since no findings match
        for req_id, req_result in results.items():
            req = fw.requirements[req_id]
            if req.checks:
                assert req_result["status"] == "not_assessed"
