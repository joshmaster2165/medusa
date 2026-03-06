"""TF-005: Privilege Escalation Surface.

Detects when a server exposes a mix of low-risk read-only tools and high-risk
destructive/privileged tools without role-based access controls, creating a
privilege escalation surface.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.schema import ROLE_PERMISSION_PARAMS


class PrivilegeEscalationSurfaceCheck(BaseCheck):
    """Detect privilege escalation surfaces from tool risk asymmetry."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools or len(snapshot.tools) < 2:
            return findings

        risky_tools: list[str] = []  # DESTRUCTIVE or PRIVILEGED
        safe_tools: list[str] = []  # READ_ONLY or UNKNOWN

        for tool in snapshot.tools:
            risk = classify_tool_risk(tool)
            tool_name = tool.get("name", "<unnamed>")
            if risk in (ToolRisk.DESTRUCTIVE, ToolRisk.PRIVILEGED):
                risky_tools.append(tool_name)
            else:
                safe_tools.append(tool_name)

        if not risky_tools or not safe_tools:
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
                        f"No privilege escalation surface detected across "
                        f"{len(snapshot.tools)} tool(s). Server does not "
                        f"expose both low-risk and high-risk tools."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        # Check if risky tools have role/permission params
        risky_set = set(risky_tools)
        unprotected_risky: list[str] = []
        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            if tool_name not in risky_set:
                continue
            props = tool.get("inputSchema", {}).get("properties", {})
            param_names_lower = {p.lower() for p in props}
            if not (param_names_lower & ROLE_PERMISSION_PARAMS):
                unprotected_risky.append(tool_name)

        if unprotected_risky:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server has {len(safe_tools)} read/low-risk "
                        f"tools and {len(unprotected_risky)} "
                        f"destructive/privileged tools without role-based "
                        f"access controls. An attacker who compromises a "
                        f"low-risk tool can escalate to destructive "
                        f"operations."
                    ),
                    evidence=(
                        f"unprotected_risky={unprotected_risky[:5]}, safe_tools={safe_tools[:5]}"
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
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"All {len(risky_tools)} destructive/privileged "
                        f"tools have role-based access control parameters."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
