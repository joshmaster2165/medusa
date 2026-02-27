"""PRIV-021: Horizontal Privilege Escalation.

Detects tools that accept user_id or account_id parameters, which if not
validated against the caller's identity, allow horizontal privilege escalation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_USER_ID_PARAMS = {
    "user_id",
    "userid",
    "account_id",
    "accountid",
    "owner_id",
    "customer_id",
    "member_id",
    "profile_id",
    "subject_id",
    "target_user_id",
}


class HorizontalPrivilegeEscalationCheck(BaseCheck):
    """Detect tools with user ID params that could enable horizontal escalation."""

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
            tool_name = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )

            # Find user-ID-like params that are unconstrained
            risky_params = [
                p
                for p in properties
                if p.lower() in _USER_ID_PARAMS
                and isinstance(properties.get(p), dict)
                and not properties[p].get("enum")
                and not properties[p].get("const")
            ]

            if not risky_params:
                continue

            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=tool_name,
                    status_extended=(
                        f"Tool '{tool_name}' accepts user identity parameter(s) "
                        f"{risky_params} without constraints, enabling horizontal "
                        f"privilege escalation to other users' data."
                    ),
                    evidence=f"Unconstrained user ID params: {risky_params}",
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
                    status_extended="No horizontal privilege escalation risk detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
