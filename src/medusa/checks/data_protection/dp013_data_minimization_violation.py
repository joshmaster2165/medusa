"""DP013: Data Minimization Violation.

Detects MCP tools that collect an excessive number of parameters, violating data minimization
principles. Excessive data collection increases the attack surface and privacy risk.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAX_PARAMS = 15


class DataMinimizationViolationCheck(BaseCheck):
    """Data Minimization Violation."""

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
            count = len(props)
            if count > _MAX_PARAMS:
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
                        status_extended=f"Tool '{tool_name}' has {count} params (threshold:"
                        f"{_MAX_PARAMS}).",
                        evidence=f"tool={tool_name}, params={count}, threshold={_MAX_PARAMS}",
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
                    status_extended=f"All tools within data minimization threshold"
                    f"({_MAX_PARAMS} params).",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
