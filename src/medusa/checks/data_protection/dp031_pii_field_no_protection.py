"""DP031: PII Field Without Protection.

Detects parameters named with PII indicators (email, phone, ssn, etc.)
that lack validation constraints such as pattern, enum, or format.
Unvalidated PII fields increase the risk of data injection and leakage.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

PII_PARAM_NAMES: set[str] = {
    "email",
    "phone",
    "ssn",
    "social_security",
    "address",
    "date_of_birth",
    "dob",
    "credit_card",
    "passport",
    "driver_license",
    "national_id",
    "tax_id",
    "phone_number",
    "full_name",
    "first_name",
    "last_name",
    "birth_date",
    "postal_code",
    "zip_code",
}


def _is_pii_param(name: str) -> str | None:
    """Return the matching PII indicator or None."""
    lowered = name.lower()
    for pii_name in PII_PARAM_NAMES:
        if pii_name in lowered:
            return pii_name
    return None


def _has_validation_constraints(param_def: dict) -> bool:
    """Check if a parameter has any validation constraints."""
    return bool(param_def.get("pattern") or param_def.get("format") or param_def.get("enum"))


class PiiFieldNoProtectionCheck(BaseCheck):
    """PII Field Without Protection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema", {})
            if not isinstance(input_schema, dict):
                continue
            properties = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                pii_match = _is_pii_param(param_name)
                if not pii_match:
                    continue

                if not _has_validation_constraints(param_def):
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=(snapshot.transport_type),
                            resource_type="tool",
                            resource_name=tool_name,
                            status_extended=(
                                f"Tool '{tool_name}' has PII "
                                f"parameter '{param_name}' "
                                f"(matched: {pii_match}) "
                                f"without validation "
                                f"constraints."
                            ),
                            evidence=(
                                f"param={param_name}, "
                                f"pii_indicator={pii_match}, "
                                f"pattern=missing, "
                                f"format=missing, "
                                f"enum=missing"
                            ),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        if not findings and snapshot.tools:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        "All PII parameters have validation "
                        f"constraints across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
