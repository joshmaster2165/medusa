"""Baseline management for finding suppression and delta tracking.

A baseline captures the fingerprints of all findings from a scan.
Subsequent scans can compare against the baseline to show only NEW
findings — or suppress known/accepted findings.

File format: `.medusa-baseline.json`
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from medusa.core.models import Finding, ScanResult, Status

logger = logging.getLogger(__name__)


class BaselineEntry(BaseModel):
    """A single fingerprinted finding in the baseline."""

    fingerprint: str
    check_id: str
    server_name: str
    resource_name: str
    severity: str
    check_title: str
    suppressed: bool = False
    suppression_reason: str | None = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Baseline(BaseModel):
    """A complete baseline snapshot."""

    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    medusa_version: str = ""
    scan_id: str = ""
    entries: list[BaselineEntry] = []


def fingerprint_finding(finding: Finding) -> str:
    """Generate a stable fingerprint for a finding.

    The fingerprint is based on the check_id, server_name,
    resource_type, resource_name, and severity — NOT the
    status_extended text (which may change between runs).
    """
    key = (
        f"{finding.check_id}:"
        f"{finding.server_name}:"
        f"{finding.resource_type}:"
        f"{finding.resource_name}:"
        f"{finding.severity.value}"
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def generate_baseline(result: ScanResult) -> Baseline:
    """Generate a baseline from a ScanResult.

    Only FAIL findings are included (PASS/ERROR/SKIPPED are excluded).
    """
    entries: list[BaselineEntry] = []
    seen: set[str] = set()

    for finding in result.findings:
        if finding.status != Status.FAIL:
            continue

        fp = fingerprint_finding(finding)
        if fp in seen:
            continue
        seen.add(fp)

        entries.append(
            BaselineEntry(
                fingerprint=fp,
                check_id=finding.check_id,
                server_name=finding.server_name,
                resource_name=finding.resource_name,
                severity=finding.severity.value,
                check_title=finding.check_title,
            )
        )

    return Baseline(
        medusa_version=result.medusa_version,
        scan_id=result.scan_id,
        entries=entries,
    )


def load_baseline(path: str | Path) -> Baseline:
    """Load a baseline from a JSON file.

    Raises
    ------
    FileNotFoundError
        If the baseline file doesn't exist.
    ValueError
        If the file is malformed.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")

    try:
        raw = json.loads(path.read_text())
        return Baseline.model_validate(raw)
    except (json.JSONDecodeError, Exception) as e:
        raise ValueError(f"Malformed baseline file: {e}") from e


def save_baseline(baseline: Baseline, path: str | Path) -> None:
    """Save a baseline to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        baseline.model_dump_json(indent=2)
    )


def filter_new_findings(
    result: ScanResult,
    baseline: Baseline,
) -> tuple[list[Finding], list[Finding], list[str]]:
    """Partition findings into new, baselined, and resolved.

    Parameters
    ----------
    result:
        The current scan result.
    baseline:
        The baseline to compare against.

    Returns
    -------
    A tuple of:
    - new_findings: FAIL findings NOT in the baseline
    - baselined_findings: FAIL findings that ARE in the baseline
    - resolved_fingerprints: baseline entries no longer present in results
    """
    baseline_fps: dict[str, BaselineEntry] = {
        entry.fingerprint: entry for entry in baseline.entries
    }
    suppressed_fps = {
        fp for fp, entry in baseline_fps.items() if entry.suppressed
    }

    new_findings: list[Finding] = []
    baselined_findings: list[Finding] = []
    seen_fps: set[str] = set()

    for finding in result.findings:
        if finding.status != Status.FAIL:
            # Non-FAIL findings pass through to new_findings
            # so they still appear in the output
            new_findings.append(finding)
            continue

        fp = fingerprint_finding(finding)
        seen_fps.add(fp)

        if fp in baseline_fps:
            baselined_findings.append(finding)
        else:
            new_findings.append(finding)

    # Find resolved: baseline entries not seen in current scan
    resolved_fps = [
        fp for fp in baseline_fps
        if fp not in seen_fps and fp not in suppressed_fps
    ]

    return new_findings, baselined_findings, resolved_fps


def suppress_finding(
    baseline: Baseline,
    fingerprint: str,
    reason: str,
) -> bool:
    """Mark a finding as suppressed in the baseline.

    Returns True if the fingerprint was found and updated.
    """
    for entry in baseline.entries:
        if entry.fingerprint == fingerprint:
            entry.suppressed = True
            entry.suppression_reason = reason
            return True
    return False


def unsuppress_finding(
    baseline: Baseline,
    fingerprint: str,
) -> bool:
    """Remove suppression from a finding in the baseline.

    Returns True if the fingerprint was found and updated.
    """
    for entry in baseline.entries:
        if entry.fingerprint == fingerprint:
            entry.suppressed = False
            entry.suppression_reason = None
            return True
    return False
