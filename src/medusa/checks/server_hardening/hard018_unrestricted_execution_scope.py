"""HARD018: Unrestricted Tool Execution Scope.

Detects servers that have both privileged tools (shell, exec, admin,
system) and exfiltrative tools (send, upload, email) without
capability restrictions. This combination enables full attack chains
from code execution to data exfiltration.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk


class UnrestrictedExecutionScopeCheck(BaseCheck):
    """Unrestricted Tool Execution Scope."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        privileged_tools: list[str] = []
        exfiltrative_tools: list[str] = []

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            risk = classify_tool_risk(tool)

            if risk == ToolRisk.PRIVILEGED:
                privileged_tools.append(tool_name)
            elif risk == ToolRisk.EXFILTRATIVE:
                exfiltrative_tools.append(tool_name)

        if privileged_tools and exfiltrative_tools:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(
                        snapshot.transport_type
                    ),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"has both privileged tools "
                        f"({len(privileged_tools)}) and "
                        f"exfiltrative tools "
                        f"({len(exfiltrative_tools)}). "
                        f"This enables full attack chains."
                    ),
                    evidence=(
                        f"privileged="
                        f"{', '.join(privileged_tools[:5])}"
                        f"; exfiltrative="
                        f"{', '.join(exfiltrative_tools[:5])}"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(
                        snapshot.transport_type
                    ),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"does not combine privileged and "
                        f"exfiltrative tools."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
