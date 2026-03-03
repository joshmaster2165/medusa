"""Unit tests for the Medusa scoring algorithm.

Tests cover:
- calculate_server_score() with various finding combinations
- score_to_grade() threshold mapping
- calculate_aggregate_score() with single and multiple servers
- apply_severity_caps() grade capping
- Edge cases (empty findings, zero checks, all same severity)
"""

from __future__ import annotations

from datetime import UTC, datetime

from medusa.core.models import Finding, ServerScore, Severity, Status
from medusa.core.scoring import (
    GRADE_THRESHOLDS,
    SEVERITY_WEIGHTS,
    apply_severity_caps,
    calculate_aggregate_score,
    calculate_server_score,
    score_to_grade,
)


def _make_finding(
    status: Status = Status.PASS,
    severity: Severity = Severity.MEDIUM,
    server_name: str = "test-server",
    check_id: str = "test-check",
) -> Finding:
    """Helper to create a Finding with minimal boilerplate."""
    return Finding(
        check_id=check_id,
        check_title="Test Check",
        status=status,
        severity=severity,
        server_name=server_name,
        server_transport="stdio",
        resource_type="tool",
        resource_name="test_tool",
        status_extended="Test finding",
        remediation="Fix it",
        timestamp=datetime.now(UTC),
    )


# ==========================================================================
# score_to_grade()
# ==========================================================================


class TestScoreToGrade:
    """Tests for the score_to_grade() function."""

    def test_perfect_score_gives_a(self) -> None:
        assert score_to_grade(10.0) == "A", "Score 10.0 should map to grade A"

    def test_score_9_gives_a(self) -> None:
        assert score_to_grade(9.0) == "A", "Score 9.0 should map to grade A"

    def test_score_8_9_gives_b(self) -> None:
        assert score_to_grade(8.9) == "B", "Score 8.9 should map to grade B"

    def test_score_7_gives_b(self) -> None:
        assert score_to_grade(7.0) == "B", "Score 7.0 should map to grade B"

    def test_score_6_9_gives_c(self) -> None:
        assert score_to_grade(6.9) == "C", "Score 6.9 should map to grade C"

    def test_score_5_gives_c(self) -> None:
        assert score_to_grade(5.0) == "C", "Score 5.0 should map to grade C"

    def test_score_4_9_gives_d(self) -> None:
        assert score_to_grade(4.9) == "D", "Score 4.9 should map to grade D"

    def test_score_3_gives_d(self) -> None:
        assert score_to_grade(3.0) == "D", "Score 3.0 should map to grade D"

    def test_score_2_9_gives_f(self) -> None:
        assert score_to_grade(2.9) == "F", "Score 2.9 should map to grade F"

    def test_score_0_gives_f(self) -> None:
        assert score_to_grade(0.0) == "F", "Score 0.0 should map to grade F"

    def test_negative_score_gives_f(self) -> None:
        assert score_to_grade(-1.0) == "F", "Negative score should map to grade F"

    def test_all_thresholds_are_covered(self) -> None:
        """Verify every grade in the threshold table is reachable."""
        expected_grades = {grade for _, grade in GRADE_THRESHOLDS}
        actual_grades = set()
        for threshold, grade in GRADE_THRESHOLDS:
            actual_grades.add(score_to_grade(threshold))
        assert expected_grades == actual_grades, (
            "Every grade defined in thresholds should be reachable"
        )


# ==========================================================================
# calculate_server_score()
# ==========================================================================


class TestCalculateServerScore:
    """Tests for the calculate_server_score() function."""

    def test_all_pass_findings_gives_perfect_score(self) -> None:
        findings = [
            _make_finding(status=Status.PASS, severity=Severity.CRITICAL),
            _make_finding(status=Status.PASS, severity=Severity.HIGH),
            _make_finding(status=Status.PASS, severity=Severity.MEDIUM),
        ]
        result = calculate_server_score(findings, total_checks_run=3)
        assert result.score == 10.0, (
            f"All PASS findings should yield score 10.0, got {result.score}"
        )
        assert result.grade == "A", "All PASS should give grade A"
        assert result.passed == 3, "Should count 3 passed"
        assert result.failed == 0, "Should count 0 failed"
        assert result.critical_findings == 0, "No critical failures"
        assert result.high_findings == 0, "No high failures"
        assert result.medium_findings == 0, "No medium failures"
        assert result.low_findings == 0, "No low failures"

    def test_single_critical_failure_capped(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL),
            _make_finding(status=Status.PASS, severity=Severity.HIGH),
            _make_finding(status=Status.PASS, severity=Severity.MEDIUM),
        ]
        result = calculate_server_score(findings, total_checks_run=3)
        # Base score = 10 - (10/30)*10 = 6.7, capped at 4.9 by CRITICAL cap
        assert result.score == 4.9, f"1 CRITICAL should cap score at 4.9, got {result.score}"
        assert result.grade == "D", f"Expected grade D with 1 CRITICAL, got {result.grade}"
        assert result.critical_findings == 1, "Should count 1 critical finding"
        assert result.failed == 1, "Should count 1 failure"
        assert result.passed == 2, "Should count 2 passed"

    def test_all_critical_failures_gives_low_score(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL),
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL),
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL),
        ]
        result = calculate_server_score(findings, total_checks_run=3)
        assert result.score == 0.0, (
            f"All CRITICAL failures should give score 0.0, got {result.score}"
        )
        assert result.grade == "F", "All CRITICAL failures should give grade F"
        assert result.critical_findings == 3, "Should count 3 critical findings"

    def test_mixed_severities_no_cap(self) -> None:
        """1 HIGH + 1 LOW: no caps apply (below thresholds)."""
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.HIGH),
            _make_finding(status=Status.FAIL, severity=Severity.LOW),
            _make_finding(status=Status.PASS, severity=Severity.MEDIUM),
            _make_finding(status=Status.PASS, severity=Severity.CRITICAL),
        ]
        result = calculate_server_score(findings, total_checks_run=4)
        # Deductions: HIGH=7.0, LOW=1.5, total=8.5
        # max_possible = 10.0 * 4 = 40.0
        # score = 10.0 - (8.5 / 40.0) * 10.0 = 10.0 - 2.125 = 7.875 -> 7.9
        # No caps: 0 CRITICAL, 1 HIGH < 5
        assert result.score == 7.9, f"Expected score 7.9 for mixed severities, got {result.score}"
        assert result.grade == "B", f"Expected grade B, got {result.grade}"
        assert result.high_findings == 1, "Should count 1 high finding"
        assert result.low_findings == 1, "Should count 1 low finding"
        assert result.failed == 2, "Should count 2 failures"
        assert result.passed == 2, "Should count 2 passed"

    def test_informational_failures_dont_affect_score(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.INFORMATIONAL),
            _make_finding(status=Status.PASS, severity=Severity.HIGH),
        ]
        result = calculate_server_score(findings, total_checks_run=2)
        assert result.score == 10.0, (
            "INFORMATIONAL failures have weight 0.0 and should not lower score"
        )
        assert result.info_findings == 1, "Should count 1 info finding"

    def test_info_findings_field(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.INFORMATIONAL, check_id="i1"),
            _make_finding(status=Status.FAIL, severity=Severity.INFORMATIONAL, check_id="i2"),
            _make_finding(status=Status.FAIL, severity=Severity.LOW, check_id="l1"),
        ]
        result = calculate_server_score(findings, total_checks_run=3)
        assert result.info_findings == 2
        assert result.low_findings == 1
        assert result.failed == 3  # all FAILs still counted in raw total

    def test_zero_checks_run_gives_zero_score(self) -> None:
        result = calculate_server_score([], total_checks_run=0)
        assert result.score == 0.0, "Zero checks run should give score 0.0"
        assert result.server_name == "unknown", (
            "Empty findings should default server_name to 'unknown'"
        )

    def test_score_is_clamped_to_0_10_range(self) -> None:
        # Even many failures cannot push score below 0
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL) for _ in range(20)
        ]
        result = calculate_server_score(findings, total_checks_run=5)
        assert result.score >= 0.0, "Score should not go below 0.0"
        assert result.score <= 10.0, "Score should not exceed 10.0"

    def test_server_name_from_findings(self) -> None:
        findings = [
            _make_finding(status=Status.PASS, server_name="my-server"),
        ]
        result = calculate_server_score(findings, total_checks_run=1)
        assert result.server_name == "my-server", "Server name should come from findings"

    def test_total_checks_field(self) -> None:
        findings = [_make_finding(status=Status.PASS)]
        result = calculate_server_score(findings, total_checks_run=10)
        assert result.total_checks == 10, "total_checks should reflect the argument passed in"

    def test_score_rounding(self) -> None:
        """Score should be rounded to one decimal place."""
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.MEDIUM),
        ]
        result = calculate_server_score(findings, total_checks_run=3)
        # Deduction = 4.0 / 30.0 * 10.0 = 1.333...
        # Score = 10.0 - 1.333... = 8.666... -> 8.7
        # No caps: 0 CRITICAL, 0 HIGH
        assert result.score == 8.7, (
            f"Score should be rounded to 1 decimal place, got {result.score}"
        )

    def test_only_low_findings(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.LOW),
            _make_finding(status=Status.FAIL, severity=Severity.LOW),
        ]
        result = calculate_server_score(findings, total_checks_run=5)
        # Deduction = 3.0 / 50.0 * 10.0 = 0.6
        # Score = 10.0 - 0.6 = 9.4
        assert result.score == 9.4, f"Expected score 9.4, got {result.score}"
        assert result.grade == "A", f"Expected grade A, got {result.grade}"


# ==========================================================================
# apply_severity_caps() — direct unit tests
# ==========================================================================


class TestApplySeverityCaps:
    """Direct tests for the apply_severity_caps function."""

    def test_no_caps_returns_original(self) -> None:
        assert apply_severity_caps(9.5, critical_count=0, high_count=0) == 9.5

    def test_critical_caps_score(self) -> None:
        assert apply_severity_caps(9.5, critical_count=1, high_count=0) == 4.9

    def test_high_caps_score(self) -> None:
        assert apply_severity_caps(9.5, critical_count=0, high_count=5) == 6.9

    def test_many_critical_floors_at_zero(self) -> None:
        # 11 CRITICAL: cap = max(0, 4.9 - 10*0.5) = max(0, -0.1) = 0.0
        assert apply_severity_caps(9.5, critical_count=11, high_count=0) == 0.0

    def test_score_below_cap_unchanged(self) -> None:
        assert apply_severity_caps(2.0, critical_count=1, high_count=0) == 2.0

    def test_high_below_threshold_no_cap(self) -> None:
        # 4 HIGH findings: below threshold of 5, no cap
        assert apply_severity_caps(9.5, critical_count=0, high_count=4) == 9.5


# ==========================================================================
# Severity caps via calculate_server_score()
# ==========================================================================


class TestSeverityCaps:
    """Tests for severity-based score capping in calculate_server_score."""

    def test_one_critical_caps_at_4_9(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL, check_id="c1"),
            *[_make_finding(status=Status.PASS, check_id=f"p{i}") for i in range(19)],
        ]
        result = calculate_server_score(findings, total_checks_run=20)
        # Base score = 10 - (10/200)*10 = 9.5, capped at 4.9
        assert result.score == 4.9
        assert result.grade == "D"

    def test_three_critical_caps_at_3_9(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL, check_id=f"c{i}")
            for i in range(3)
        ] + [_make_finding(status=Status.PASS, check_id=f"p{i}") for i in range(17)]
        result = calculate_server_score(findings, total_checks_run=20)
        # Cap = max(0, 4.9 - 2*0.5) = 3.9
        assert result.score == 3.9
        assert result.grade == "D"

    def test_ten_critical_caps_near_zero(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL, check_id=f"c{i}")
            for i in range(10)
        ] + [_make_finding(status=Status.PASS, check_id=f"p{i}") for i in range(90)]
        result = calculate_server_score(findings, total_checks_run=100)
        # Cap = max(0, 4.9 - 9*0.5) = max(0, 0.4) = 0.4
        assert result.score == 0.4
        assert result.grade == "F"

    def test_five_high_caps_at_6_9(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.HIGH, check_id=f"h{i}")
            for i in range(5)
        ] + [_make_finding(status=Status.PASS, check_id=f"p{i}") for i in range(95)]
        result = calculate_server_score(findings, total_checks_run=100)
        # Base = 10 - (35/1000)*10 = 9.65 -> 9.7, capped at 6.9
        assert result.score == 6.9
        assert result.grade == "C"

    def test_thirty_four_high_caps_low(self) -> None:
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.HIGH, check_id=f"h{i}")
            for i in range(34)
        ] + [_make_finding(status=Status.PASS, check_id=f"p{i}") for i in range(66)]
        result = calculate_server_score(findings, total_checks_run=100)
        # Cap = max(0, 6.9 - 29*0.1) = max(0, 4.0) = 4.0
        assert result.score == 4.0
        assert result.grade == "D"

    def test_critical_cap_overrides_high_cap(self) -> None:
        """When both CRITICAL and HIGH caps apply, the stricter wins."""
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL, check_id="c1"),
            *[
                _make_finding(status=Status.FAIL, severity=Severity.HIGH, check_id=f"h{i}")
                for i in range(10)
            ],
            *[_make_finding(status=Status.PASS, check_id=f"p{i}") for i in range(89)],
        ]
        result = calculate_server_score(findings, total_checks_run=100)
        # CRITICAL cap = 4.9, HIGH cap = max(0, 6.9 - 5*0.1) = 6.4
        # min(4.9, 6.4) = 4.9
        assert result.score == 4.9
        assert result.grade == "D"

    def test_base_score_below_cap_not_raised(self) -> None:
        """Caps only lower, never raise the score."""
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.CRITICAL, check_id=f"c{i}")
            for i in range(3)
        ]
        result = calculate_server_score(findings, total_checks_run=3)
        # Base score = 0.0 (all 3 checks are CRITICAL fails)
        # Cap = 3.9, but base is already lower
        assert result.score == 0.0
        assert result.grade == "F"

    def test_no_cap_when_below_thresholds(self) -> None:
        """No caps apply when CRITICAL=0 and HIGH<5."""
        findings = [
            _make_finding(status=Status.FAIL, severity=Severity.HIGH, check_id=f"h{i}")
            for i in range(4)
        ] + [_make_finding(status=Status.PASS, check_id=f"p{i}") for i in range(96)]
        result = calculate_server_score(findings, total_checks_run=100)
        # Base = 10 - (28/1000)*10 = 10 - 0.28 = 9.72 -> 9.7
        # No caps apply (4 HIGH < threshold of 5)
        assert result.score == 9.7
        assert result.grade == "A"


# ==========================================================================
# calculate_aggregate_score()
# ==========================================================================


class TestCalculateAggregateScore:
    """Tests for the calculate_aggregate_score() function."""

    def test_single_server(self) -> None:
        scores = [
            ServerScore(
                server_name="server-a",
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
        ]
        result = calculate_aggregate_score(scores)
        assert result == 8.5, f"Single server aggregate should equal its score, got {result}"

    def test_multiple_servers_weighted_average(self) -> None:
        scores = [
            ServerScore(
                server_name="server-a",
                score=10.0,
                grade="A",
                total_checks=10,
                passed=10,
                failed=0,
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
            ),
            ServerScore(
                server_name="server-b",
                score=5.0,
                grade="C",
                total_checks=10,
                passed=5,
                failed=5,
                critical_findings=2,
                high_findings=3,
                medium_findings=0,
                low_findings=0,
            ),
        ]
        result = calculate_aggregate_score(scores)
        # Weighted: (10.0 * 10 + 5.0 * 10) / 20 = 150 / 20 = 7.5
        assert result == 7.5, f"Expected 7.5, got {result}"

    def test_weighted_by_check_count(self) -> None:
        """Server with more checks should have more weight."""
        scores = [
            ServerScore(
                server_name="small",
                score=2.0,
                grade="F",
                total_checks=2,
                passed=0,
                failed=2,
                critical_findings=2,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
            ),
            ServerScore(
                server_name="large",
                score=9.0,
                grade="A",
                total_checks=18,
                passed=16,
                failed=2,
                critical_findings=0,
                high_findings=0,
                medium_findings=2,
                low_findings=0,
            ),
        ]
        result = calculate_aggregate_score(scores)
        # Weighted: (2.0 * 2 + 9.0 * 18) / 20 = (4 + 162) / 20 = 166 / 20 = 8.3
        assert result == 8.3, f"Expected 8.3, got {result}"

    def test_empty_server_scores_gives_perfect(self) -> None:
        result = calculate_aggregate_score([])
        assert result == 10.0, "No servers scanned should default to 10.0 (no findings = no risk)"

    def test_all_zero_check_counts_gives_perfect(self) -> None:
        scores = [
            ServerScore(
                server_name="empty",
                score=0.0,
                grade="F",
                total_checks=0,
                passed=0,
                failed=0,
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
            ),
        ]
        result = calculate_aggregate_score(scores)
        assert result == 10.0, "All servers with 0 checks should give aggregate score 10.0"

    def test_aggregate_score_is_rounded(self) -> None:
        scores = [
            ServerScore(
                server_name="a",
                score=7.3,
                grade="B",
                total_checks=3,
                passed=2,
                failed=1,
                critical_findings=0,
                high_findings=0,
                medium_findings=1,
                low_findings=0,
            ),
            ServerScore(
                server_name="b",
                score=8.1,
                grade="B",
                total_checks=7,
                passed=6,
                failed=1,
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=1,
            ),
        ]
        result = calculate_aggregate_score(scores)
        # Weighted: (7.3 * 3 + 8.1 * 7) / 10 = (21.9 + 56.7) / 10 = 78.6 / 10 = 7.86 -> 7.9
        assert result == 7.9, f"Expected 7.9 (rounded), got {result}"

    def test_all_perfect_scores(self) -> None:
        scores = [
            ServerScore(
                server_name=f"server-{i}",
                score=10.0,
                grade="A",
                total_checks=5,
                passed=5,
                failed=0,
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
            )
            for i in range(5)
        ]
        result = calculate_aggregate_score(scores)
        assert result == 10.0, "All perfect scores should give aggregate 10.0"


# ==========================================================================
# Severity weights sanity checks
# ==========================================================================


class TestSeverityWeights:
    """Verify the severity weight constants are sensible."""

    def test_critical_is_highest_weight(self) -> None:
        assert SEVERITY_WEIGHTS[Severity.CRITICAL] == 10.0, "CRITICAL should have weight 10.0"

    def test_informational_is_zero_weight(self) -> None:
        assert SEVERITY_WEIGHTS[Severity.INFORMATIONAL] == 0.0, (
            "INFORMATIONAL should have weight 0.0"
        )

    def test_weights_are_in_descending_order(self) -> None:
        ordered_severities = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFORMATIONAL,
        ]
        weights = [SEVERITY_WEIGHTS[s] for s in ordered_severities]
        assert weights == sorted(weights, reverse=True), (
            "Weights should be in descending order from CRITICAL to INFORMATIONAL"
        )

    def test_all_severities_have_weights(self) -> None:
        for severity in Severity:
            assert severity in SEVERITY_WEIGHTS, (
                f"Severity {severity} is missing from SEVERITY_WEIGHTS"
            )
