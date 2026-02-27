"""Compliance framework loader and mapper."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel

from medusa.core.models import Finding, Status


class FrameworkRequirement(BaseModel):
    """A single requirement in a compliance framework."""

    title: str
    checks: list[str]


class ComplianceFramework(BaseModel):
    """A compliance framework with requirements mapped to checks."""

    name: str
    version: str
    url: str = ""
    requirements: dict[str, FrameworkRequirement]


def load_framework(name: str) -> ComplianceFramework:
    """Load a built-in compliance framework by name."""
    frameworks_dir = Path(__file__).parent
    framework_path = frameworks_dir / f"{name}.yaml"

    if not framework_path.exists():
        raise FileNotFoundError(f"Compliance framework not found: {name}")

    data = yaml.safe_load(framework_path.read_text())
    framework_data = data.get("framework", {})
    requirements_data = data.get("requirements", {})

    requirements = {}
    for req_id, req_info in requirements_data.items():
        requirements[req_id] = FrameworkRequirement(
            title=req_info.get("title", ""),
            checks=req_info.get("checks", []),
        )

    return ComplianceFramework(
        name=framework_data.get("name", name),
        version=framework_data.get("version", ""),
        url=framework_data.get("url", ""),
        requirements=requirements,
    )


def evaluate_compliance(
    framework: ComplianceFramework,
    findings: list[Finding],
) -> dict[str, dict]:
    """Evaluate scan findings against a compliance framework.

    Returns a dict mapping requirement IDs to their compliance status.
    """
    # Build lookup: check_id -> list of findings
    findings_by_check: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_check.setdefault(finding.check_id, []).append(finding)

    results: dict[str, dict] = {}

    for req_id, requirement in framework.requirements.items():
        if not requirement.checks:
            results[req_id] = {
                "title": requirement.title,
                "status": "not_assessed",
                "checks_total": 0,
                "checks_passed": 0,
                "checks_failed": 0,
                "details": [],
            }
            continue

        checks_passed = 0
        checks_failed = 0
        details: list[dict] = []

        for check_id in requirement.checks:
            check_findings = findings_by_check.get(check_id, [])
            if not check_findings:
                details.append(
                    {
                        "check_id": check_id,
                        "status": "not_run",
                    }
                )
                continue

            has_fail = any(f.status == Status.FAIL for f in check_findings)
            if has_fail:
                checks_failed += 1
                details.append(
                    {
                        "check_id": check_id,
                        "status": "fail",
                        "finding_count": sum(1 for f in check_findings if f.status == Status.FAIL),
                    }
                )
            else:
                checks_passed += 1
                details.append(
                    {
                        "check_id": check_id,
                        "status": "pass",
                    }
                )

        total = checks_passed + checks_failed
        if total == 0:
            status = "not_assessed"
        elif checks_failed == 0:
            status = "compliant"
        else:
            status = "non_compliant"

        results[req_id] = {
            "title": requirement.title,
            "status": status,
            "checks_total": len(requirement.checks),
            "checks_passed": checks_passed,
            "checks_failed": checks_failed,
            "details": details,
        }

    return results
