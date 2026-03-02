"""AGENT-024: Unrestricted Tool Output.

Detects tools that have no output schema or size constraints, allowing
unlimited data return. Unrestricted output can be used for data
exfiltration or context flooding. Only flags tools classified as
READ_ONLY or EXFILTRATIVE by risk analysis.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk


class UnrestrictedToolOutputCheck(BaseCheck):
    """Unrestricted Tool Output."""

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
            tool_name = tool.get("name", "unknown")

            # Only flag tools that are READ_ONLY or EXFILTRATIVE
            risk = classify_tool_risk(tool)
            if risk not in (ToolRisk.READ_ONLY, ToolRisk.EXFILTRATIVE):
                continue

            # Check if the tool defines an outputSchema
            output_schema = tool.get("outputSchema")
            if output_schema:
                continue

            risk_label = (
                "data-reading" if risk == ToolRisk.READ_ONLY else "potentially exfiltrative"
            )
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
                        f"Tool '{tool_name}' is {risk_label} but has no outputSchema "
                        f"defined. Without output constraints, the tool can return "
                        f"arbitrarily large or malicious responses."
                    ),
                    evidence=(f"Tool: {tool_name}, Risk: {risk.value}, outputSchema: missing"),
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
                    status_extended=(
                        "No data-reading or exfiltrative tools with unrestricted output detected."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings
