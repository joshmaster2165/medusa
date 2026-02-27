"""TP021: Tool Capability Escalation.

Detects tools that request or imply capabilities beyond their stated purpose. For example, a
tool described as a "text formatter" that accepts file path parameters or network URLs indicates
capability escalation beyond its documented scope.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.injection import CAPABILITY_ESCALATION_KEYWORDS


class ToolCapabilityEscalationCheck(BaseCheck):
    """Tool Capability Escalation."""

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
            description: str = tool.get("description", "")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            hits: list[str] = []

            # Check description words against escalation keywords
            desc_words = set(description.lower().split())
            for kw in CAPABILITY_ESCALATION_KEYWORDS:
                if kw in desc_words:
                    hits.append(f"description contains '{kw}'")

            # Check parameter names
            for param_name in properties:
                normalised = param_name.lower().strip()
                if normalised in CAPABILITY_ESCALATION_KEYWORDS:
                    hits.append(f"param name '{param_name}' is escalation keyword")

            if hits:
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
                            f"Tool '{tool_name}' contains capability escalation "
                            f"indicators: {'; '.join(hits[:5])}"
                        ),
                        evidence="; ".join(hits[:5]),
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
                        f"No capability escalation indicators detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
