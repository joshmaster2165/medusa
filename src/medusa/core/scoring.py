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

# ---------------------------------------------------------------------------
# Severity-based score caps
# ---------------------------------------------------------------------------
# Prevent inflated grades when critical/high findings exist, regardless of
# how many checks pass overall.

CRITICAL_CAP_BASE: float = 6.9  # 1 CRITICAL → max score 6.9 (Grade C)
CRITICAL_CAP_DECAY: float = 0.3  # Each additional CRITICAL lowers cap by 0.3

HIGH_CAP_THRESHOLD: int = 5  # Caps kick in at ≥ 5 HIGH findings
HIGH_CAP_BASE: float = 7.9  # 5 HIGH → max score 7.9 (Grade B)
HIGH_CAP_DECAY: float = 0.05  # Each additional HIGH beyond 5 lowers cap by 0.05


def score_to_grade(score: float) -> str:
    """Convert a numeric score (0-10) to a letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def apply_severity_caps(
    score: float,
    critical_count: int,
    high_count: int,
) -> float:
    """Apply severity-based score caps.

    Even if the percentage-based score is high, the presence of
    CRITICAL or many HIGH findings caps the maximum achievable score.

    Returns the capped score (may be lower than input, never higher).
    """
    cap = 10.0

    if critical_count >= 1:
        critical_cap = max(0.0, CRITICAL_CAP_BASE - (critical_count - 1) * CRITICAL_CAP_DECAY)
        cap = min(cap, critical_cap)

    if high_count >= HIGH_CAP_THRESHOLD:
        high_cap = max(0.0, HIGH_CAP_BASE - (high_count - HIGH_CAP_THRESHOLD) * HIGH_CAP_DECAY)
        cap = min(cap, high_cap)

    return min(score, round(cap, 1))


def calculate_server_score(findings: list[Finding], total_checks_run: int) -> ServerScore:
    """Calculate a security score for a single server.

    Score = 10.0 - (weighted_deductions / max_possible_deduction) * 10.0
    Clamped to [0.0, 10.0], then severity caps applied.
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

    critical_count = sum(
        1 for f in findings if f.status == Status.FAIL and f.severity == Severity.CRITICAL
    )
    high_count = sum(1 for f in findings if f.status == Status.FAIL and f.severity == Severity.HIGH)

    # Apply severity-based caps after computing the base score
    if total_checks_run > 0:
        score = apply_severity_caps(score, critical_count, high_count)

    return ServerScore(
        server_name=findings[0].server_name if findings else "unknown",
        score=score,
        grade=score_to_grade(score),
        total_checks=total_checks_run,
        passed=passed,
        failed=failed_count,
        critical_findings=critical_count,
        high_findings=high_count,
        medium_findings=sum(
            1 for f in findings if f.status == Status.FAIL and f.severity == Severity.MEDIUM
        ),
        low_findings=sum(
            1 for f in findings if f.status == Status.FAIL and f.severity == Severity.LOW
        ),
        info_findings=sum(
            1 for f in findings if f.status == Status.FAIL and f.severity == Severity.INFORMATIONAL
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
