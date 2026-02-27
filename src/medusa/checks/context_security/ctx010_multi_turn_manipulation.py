"""CTX010: Multi-Turn Conversation Manipulation.

Detects patterns of progressive manipulation across multiple conversation turns. Multi-turn
attacks incrementally shift the LLM's behavior over several exchanges to bypass single-turn
safety checks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MANIPULATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"previous\s+conversation", re.IGNORECASE),
    re.compile(r"earlier\s+you\s+said", re.IGNORECASE),
    re.compile(r"you\s+already\s+agreed", re.IGNORECASE),
    re.compile(r"as\s+we\s+discussed", re.IGNORECASE),
    re.compile(r"continue\s+from", re.IGNORECASE),
    re.compile(r"remember\s+when", re.IGNORECASE),
    re.compile(r"in\s+our\s+last", re.IGNORECASE),
    re.compile(r"you\s+previously", re.IGNORECASE),
    re.compile(r"we\s+established\s+that", re.IGNORECASE),
    re.compile(r"building\s+on\s+our\s+prior", re.IGNORECASE),
    re.compile(r"per\s+your\s+earlier\s+instruction", re.IGNORECASE),
]


class MultiTurnManipulationCheck(BaseCheck):
    """Multi-Turn Conversation Manipulation."""

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
            desc = tool.get("description") or ""
            matched: list[str] = []
            for pat in _MANIPULATION_PATTERNS:
                if pat.search(desc):
                    matched.append(pat.pattern)
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
                            f"Tool '{tool_name}' description contains multi-turn "
                            f"manipulation patterns."
                        ),
                        evidence=f"patterns={', '.join(matched[:3])}",
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
                        f"No multi-turn manipulation patterns detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
