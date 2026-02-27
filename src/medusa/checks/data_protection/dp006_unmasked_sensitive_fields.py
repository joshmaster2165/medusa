"""DP006: Unmasked Sensitive Data Fields.

Detects MCP tool parameters that accept sensitive data (passwords, SSNs, credit cards) without
writeOnly or masking hints. Unmasked sensitive fields may be visible in logs, traces, or UI.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_PII_PARAM_NAMES: set[str] = {
    "password",
    "passwd",
    "secret",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "pin",
    "api_key",
    "token",
    "access_token",
    "private_key",
    "secret_key",
    "bank_account",
}


class UnmaskedSensitiveFieldsCheck(BaseCheck):
    """Unmasked Sensitive Data Fields."""

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
            schema = tool.get("inputSchema") or {}
            props = schema.get("properties") or {}
            for pname, pdef in props.items():
                if pname.lower() not in _PII_PARAM_NAMES:
                    continue
                if pdef.get("writeOnly"):
                    continue
                if pdef.get("format") == "password":
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
                        status_extended=f"Tool '{tool_name}' param '{pname}' handles sensitive"
                        f"data without writeOnly or masking.",
                        evidence=f"tool={tool_name}, param={pname}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings:
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
                    status_extended=f"No unmasked sensitive fields across {len(snapshot.tools)}"
                    f"tool(s).",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
