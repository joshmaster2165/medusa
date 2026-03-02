"""Scan result diffing — compare two scans to identify changes.

Produces a structured diff showing new findings, resolved findings,
severity changes, and score changes between two scan results.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from medusa.core.baseline import fingerprint_finding
from medusa.core.models import Finding, ScanResult, Status

logger = logging.getLogger(__name__)


class FindingChange(BaseModel):
    """A single finding that changed between scans."""

    fingerprint: str
    check_id: str
    check_title: str
    server_name: str
    resource_name: str
    severity: str
    status_extended: str = ""
    evidence: str | None = None
    remediation: str = ""


class SeverityChange(BaseModel):
    """A finding whose severity changed between scans."""

    fingerprint: str
    check_id: str
    server_name: str
    resource_name: str
    old_severity: str
    new_severity: str


class ServerScoreChange(BaseModel):
    """Score change for a single server."""

    server_name: str
    old_score: float
    new_score: float
    old_grade: str
    new_grade: str
    score_delta: float


class ScanDiff(BaseModel):
    """Complete diff between two scan results."""

    before_scan_id: str
    after_scan_id: str
    before_timestamp: datetime
    after_timestamp: datetime
    new_findings: list[FindingChange] = []
    resolved_findings: list[FindingChange] = []
    severity_changes: list[SeverityChange] = []
    server_score_changes: list[ServerScoreChange] = []

    # Summary stats
    total_new: int = 0
    total_resolved: int = 0
    total_severity_changes: int = 0
    aggregate_score_before: float = 0.0
    aggregate_score_after: float = 0.0
    aggregate_grade_before: str = ""
    aggregate_grade_after: str = ""

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def _finding_to_change(finding: Finding) -> FindingChange:
    """Convert a Finding to a FindingChange for the diff."""
    return FindingChange(
        fingerprint=fingerprint_finding(finding),
        check_id=finding.check_id,
        check_title=finding.check_title,
        server_name=finding.server_name,
        resource_name=finding.resource_name,
        severity=finding.severity.value,
        status_extended=finding.status_extended,
        evidence=finding.evidence,
        remediation=finding.remediation,
    )


def diff_scan_results(
    before: ScanResult,
    after: ScanResult,
) -> ScanDiff:
    """Compute the diff between two scan results.

    Parameters
    ----------
    before:
        The older/reference scan result.
    after:
        The newer scan result.

    Returns
    -------
    A ScanDiff with new findings, resolved findings, severity
    changes, and score changes.
    """
    # Index FAIL findings by fingerprint
    before_fails: dict[str, Finding] = {}
    for f in before.findings:
        if f.status == Status.FAIL:
            fp = fingerprint_finding(f)
            before_fails[fp] = f

    after_fails: dict[str, Finding] = {}
    for f in after.findings:
        if f.status == Status.FAIL:
            fp = fingerprint_finding(f)
            after_fails[fp] = f

    # New findings: in after but not in before
    new_findings = [
        _finding_to_change(after_fails[fp])
        for fp in after_fails
        if fp not in before_fails
    ]

    # Resolved findings: in before but not in after
    resolved_findings = [
        _finding_to_change(before_fails[fp])
        for fp in before_fails
        if fp not in after_fails
    ]

    # Severity changes: in both but severity differs
    severity_changes: list[SeverityChange] = []
    for fp in after_fails:
        if fp in before_fails:
            old_sev = before_fails[fp].severity.value
            new_sev = after_fails[fp].severity.value
            if old_sev != new_sev:
                severity_changes.append(
                    SeverityChange(
                        fingerprint=fp,
                        check_id=after_fails[fp].check_id,
                        server_name=after_fails[fp].server_name,
                        resource_name=after_fails[fp].resource_name,
                        old_severity=old_sev,
                        new_severity=new_sev,
                    )
                )

    # Server score changes
    before_scores = {s.server_name: s for s in before.server_scores}
    after_scores = {s.server_name: s for s in after.server_scores}
    all_servers = set(before_scores.keys()) | set(after_scores.keys())

    server_score_changes: list[ServerScoreChange] = []
    for srv in sorted(all_servers):
        old = before_scores.get(srv)
        new = after_scores.get(srv)
        old_score = old.score if old else 10.0
        new_score = new.score if new else 10.0
        old_grade = old.grade if old else "A"
        new_grade = new.grade if new else "A"
        if old_score != new_score:
            server_score_changes.append(
                ServerScoreChange(
                    server_name=srv,
                    old_score=old_score,
                    new_score=new_score,
                    old_grade=old_grade,
                    new_grade=new_grade,
                    score_delta=round(new_score - old_score, 1),
                )
            )

    # Sort new findings by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    new_findings.sort(key=lambda f: severity_order.get(f.severity, 5))
    resolved_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    return ScanDiff(
        before_scan_id=before.scan_id,
        after_scan_id=after.scan_id,
        before_timestamp=before.timestamp,
        after_timestamp=after.timestamp,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        severity_changes=severity_changes,
        server_score_changes=server_score_changes,
        total_new=len(new_findings),
        total_resolved=len(resolved_findings),
        total_severity_changes=len(severity_changes),
        aggregate_score_before=before.aggregate_score,
        aggregate_score_after=after.aggregate_score,
        aggregate_grade_before=before.aggregate_grade,
        aggregate_grade_after=after.aggregate_grade,
    )
