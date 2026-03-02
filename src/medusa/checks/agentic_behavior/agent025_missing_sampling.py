"""AGENT-025: Missing Sampling Capability.

Detects servers that have destructive or privileged tools but do not
declare the sampling capability, meaning the server cannot request
human review before executing dangerous operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk


class MissingSamplingCheck(BaseCheck):
    """Missing Sampling Capability."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(
        self, snapshot: ServerSnapshot
    ) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Classify all tools and find dangerous ones
        dangerous_tools: list[str] = []
        for tool in snapshot.tools:
            risk = classify_tool_risk(tool)
            if risk in (
                ToolRisk.DESTRUCTIVE,
                ToolRisk.PRIVILEGED,
            ):
                dangerous_tools.append(
                    tool.get("name", "unknown")
                )

        if not dangerous_tools:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    "No destructive or privileged tools "
                    "detected; sampling capability not "
                    "required."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
            return findings

        # Check if server declares sampling capability
        has_sampling = bool(
            snapshot.capabilities.get("sampling")
        )

        if has_sampling:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    "Server declares sampling capability "
                    "and has destructive/privileged tools. "
                    "Human review can be requested before "
                    "dangerous operations."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
        else:
            sample = dangerous_tools[:5]
            suffix = ""
            if len(dangerous_tools) > 5:
                suffix = (
                    f" and {len(dangerous_tools) - 5} more"
                )
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.FAIL,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    f"Server has "
                    f"{len(dangerous_tools)} destructive/"
                    f"privileged tool(s) but does not "
                    f"declare the 'sampling' capability. "
                    f"The server cannot request human "
                    f"review before executing dangerous "
                    f"operations."
                ),
                evidence=(
                    f"Dangerous tools: "
                    f"{', '.join(sample)}{suffix}"
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))

        return findings
