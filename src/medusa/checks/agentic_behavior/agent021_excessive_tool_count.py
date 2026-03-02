"""AGENT-021: Excessive Tool Count.

Detects servers exposing an excessive number of tools. Large tool counts
increase the attack surface, make security review harder, and may
overwhelm LLM context windows with tool definitions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status

_THRESHOLD_MEDIUM = 50
_THRESHOLD_HIGH = 100


class ExcessiveToolCountCheck(BaseCheck):
    """Excessive Tool Count."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        tool_count = len(snapshot.tools)

        if tool_count > _THRESHOLD_MEDIUM:
            # Escalate severity for very large counts
            if tool_count > _THRESHOLD_HIGH:
                effective_severity = Severity.HIGH
                level = "critically excessive"
            else:
                effective_severity = meta.severity
                level = "excessive"

            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.FAIL,
                severity=effective_severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    f"Server '{snapshot.server_name}' exposes {tool_count} tools, "
                    f"which is {level} (threshold: >{_THRESHOLD_MEDIUM}). Large tool "
                    f"counts increase attack surface and may overwhelm LLM context."
                ),
                evidence=f"Tool count: {tool_count}",
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))

        if not findings:
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
                    f"Server '{snapshot.server_name}' exposes {tool_count} tools, "
                    f"within acceptable limits."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
        return findings
