"""AGENT-010: Agent Impersonation.

Scans tool descriptions for patterns suggesting an agent or tool is
impersonating another system, agent, or trusted authority.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.injection import JAILBREAK_PATTERNS

IMPERSONATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"pretend\s+(to\s+be|you\s+are|I\s+am)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(an?\s+)?(admin|system|agent|assistant|user|bot)", re.IGNORECASE),
    re.compile(r"impersonat(e|ing)", re.IGNORECASE),
    re.compile(r"(I\s+am|you\s+are)\s+(the\s+)?(system|admin|root|god|owner)", re.IGNORECASE),
    re.compile(r"role[-_]?play\s+as\s+(an?\s+)?(admin|system|agent)", re.IGNORECASE),
]


class AgentImpersonationCheck(BaseCheck):
    """Agent Impersonation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []
        all_patterns = IMPERSONATION_PATTERNS + JAILBREAK_PATTERNS

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            combined = f"{tool.get('name', '')} {tool.get('description', '')}"
            matched = [p.pattern for p in all_patterns if p.search(combined)]
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
                            f"Tool '{tool_name}' contains impersonation patterns: '{matched[0]}'"
                        ),
                        evidence=f"matched={matched[:3]}",
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
                    status_extended="No agent impersonation patterns detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
