"""Security scoring algorithm for Medusa."""

from __future__ import annotations

from medusa.core.models import Finding, ServerScore, Severity, Status

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.5,
    Severity.INFORMATIONAL: 0.0,
}

GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (9.0, "A"),
    (7.0, "B"),
    (5.0, "C"),
    (3.0, "D"),
    (0.0, "F"),
]


def score_to_grade(score: float) -> str:
    """Convert a numeric score (0-10) to a letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def calculate_server_score(findings: list[Finding], total_checks_run: int) -> ServerScore:
    """Calculate a security score for a single server.

    Score = 10.0 - (weighted_deductions / max_possible_deduction) * 10.0
    Clamped to [0.0, 10.0].
    """
    if total_checks_run == 0:
        score = 0.0
    else:
        failed = [f for f in findings if f.status == Status.FAIL]
        weighted_deductions = sum(SEVERITY_WEIGHTS[f.severity] for f in failed)
        max_possible = 10.0 * total_checks_run
        score = 10.0 - (weighted_deductions / max_possible) * 10.0
        score = max(0.0, min(10.0, round(score, 1)))

    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed_count = sum(1 for f in findings if f.status == Status.FAIL)

    return ServerScore(
        server_name=findings[0].server_name if findings else "unknown",
        score=score,
        grade=score_to_grade(score),
        total_checks=total_checks_run,
        passed=passed,
        failed=failed_count,
        critical_findings=sum(
            1 for f in findings if f.status == Status.FAIL and f.severity == Severity.CRITICAL
        ),
        high_findings=sum(
            1 for f in findings if f.status == Status.FAIL and f.severity == Severity.HIGH
        ),
        medium_findings=sum(
            1 for f in findings if f.status == Status.FAIL and f.severity == Severity.MEDIUM
        ),
        low_findings=sum(
            1 for f in findings if f.status == Status.FAIL and f.severity == Severity.LOW
        ),
    )


def calculate_aggregate_score(server_scores: list[ServerScore]) -> float:
    """Calculate aggregate score across all servers.

    Weighted average where servers with more checks have more weight.
    """
    if not server_scores:
        return 10.0

    total_weight = sum(s.total_checks for s in server_scores)
    if total_weight == 0:
        return 10.0

    weighted_sum = sum(s.score * s.total_checks for s in server_scores)
    return round(weighted_sum / total_weight, 1)
