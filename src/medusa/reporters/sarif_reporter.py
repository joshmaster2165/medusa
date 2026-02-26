"""SARIF 2.1.0 report generator for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any

from medusa.core.models import Finding, ScanResult, Severity, Status
from medusa.reporters.base import BaseReporter

# SARIF severity mapping.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}

_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "4.0",
    Severity.LOW: "1.5",
    Severity.INFORMATIONAL: "0.0",
}

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
    "/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)


def _build_rule(finding: Finding) -> dict[str, Any]:
    """Build a SARIF rule object from a finding."""
    return {
        "id": finding.check_id,
        "name": finding.check_id.replace("-", ""),
        "shortDescription": {
            "text": finding.check_title,
        },
        "helpUri": (
            "https://github.com/joshmaster2165/medusa"
        ),
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(
                finding.severity, "0.0"
            ),
            "tags": [
                "security",
                *finding.owasp_mcp,
            ],
        },
    }


def _build_result(finding: Finding) -> dict[str, Any]:
    """Build a SARIF result object from a finding."""
    # Construct a synthetic artifact URI following the pattern:
    # mcp://server-name/resource-type/resource-name
    artifact_uri = (
        f"mcp://{finding.server_name}"
        f"/{finding.resource_type}"
        f"/{finding.resource_name}"
    )
    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "level": _SARIF_LEVEL.get(finding.severity, "note"),
        "message": {
            "text": finding.status_extended,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                    },
                },
                "logicalLocations": [
                    {
                        "name": finding.resource_name,
                        "kind": finding.resource_type,
                        "fullyQualifiedName": (
                            f"{finding.server_name}"
                            f"/{finding.resource_type}"
                            f"/{finding.resource_name}"
                        ),
                    }
                ],
            }
        ],
        "properties": {
            "severity": finding.severity.value,
            "server_name": finding.server_name,
            "server_transport": finding.server_transport,
        },
    }
    if finding.evidence:
        result["properties"]["evidence"] = finding.evidence
    if finding.remediation:
        result["fixes"] = [
            {
                "description": {
                    "text": finding.remediation,
                },
            }
        ]
    return result


class SarifReporter(BaseReporter):
    """Generate SARIF 2.1.0 JSON output.

    Produces output compatible with GitHub Code Scanning, Snyk, Semgrep,
    and other SARIF consumers.
    """

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def generate(self, result: ScanResult) -> str:
        """Generate a SARIF 2.1.0 JSON string from scan results."""
        # Only include FAIL findings as SARIF results.
        fail_findings = [
            f for f in result.findings if f.status == Status.FAIL
        ]

        # Deduplicate rules by check_id.
        seen_rule_ids: set[str] = set()
        rules: list[dict[str, Any]] = []
        for finding in fail_findings:
            if finding.check_id not in seen_rule_ids:
                seen_rule_ids.add(finding.check_id)
                rules.append(_build_rule(finding))

        results = [_build_result(f) for f in fail_findings]

        sarif: dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Medusa",
                            "version": result.medusa_version,
                            "informationUri": (
                                "https://github.com/"
                                "joshmaster2165/medusa"
                            ),
                            "rules": rules,
                        },
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "properties": {
                                "scan_id": result.scan_id,
                                "servers_scanned": (
                                    result.servers_scanned
                                ),
                                "scan_duration_seconds": (
                                    result.scan_duration_seconds
                                ),
                                "aggregate_score": (
                                    result.aggregate_score
                                ),
                                "aggregate_grade": (
                                    result.aggregate_grade
                                ),
                            },
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif, indent=self.indent)
