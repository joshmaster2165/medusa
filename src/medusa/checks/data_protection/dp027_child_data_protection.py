"""DP027: Child Data Protection (COPPA).

Detects MCP tools that may process children's data without implementing COPPA-required
protections. Tools accessible to children or processing data about minors must comply with
enhanced privacy requirements.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_KEYWORDS: set[str] = {
    "child",
    "minor",
    "coppa",
    "age_verification",
    "parental_consent",
    "kids",
    "underage",
    "age_gate",
}


class ChildDataProtectionCheck(BaseCheck):
    """Child Data Protection (COPPA)."""

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
            desc = (tool.get("description") or "").lower()
            name_lower = tool_name.lower()
            combined = name_lower + " " + desc

            matched = [kw for kw in _KEYWORDS if kw in combined]
            if matched:
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
                            f"Tool '{tool_name}' may access sensitive data: "
                            f"{', '.join(matched[:3])}"
                        ),
                        evidence=f"tool={tool_name}, keywords={', '.join(matched[:3])}",
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
                    status_extended=f"No sensitive data access indicators across"
                    f"{len(snapshot.tools)} tool(s).",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
