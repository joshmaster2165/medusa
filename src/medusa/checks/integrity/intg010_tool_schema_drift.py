"""INTG010: Tool Schema Drift.

Detects MCP tools whose inputSchema definitions are incomplete, missing descriptions, or have
drifted from a well-defined schema. Poorly-defined tool schemas make it harder for LLMs to use
tools correctly and increase the risk of unintended operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class ToolSchemaDriftCheck(BaseCheck):
    """Tool Schema Drift."""

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
            issues: list[str] = []
            if not tool.get("description"):
                issues.append("missing description")
            schema = tool.get("inputSchema") or {}
            if not schema:
                issues.append("empty inputSchema")
            elif not schema.get("properties"):
                if schema.get("type") == "object":
                    issues.append("object schema with no properties")

            if issues:
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
                            f"Tool '{tool_name}' has schema issues: {', '.join(issues)}"
                        ),
                        evidence=f"tool={tool_name}, issues={'; '.join(issues)}",
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
                        f"All {len(snapshot.tools)} tool(s) have complete schema definitions."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
