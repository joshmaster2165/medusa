"""AGENT-017: Agent Self-Modification.

Detects tools that can modify their own definitions, constraints,
instructions, or safety parameters — allowing an agent to remove
its own guardrails.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

SELF_MODIFY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(update|modify|change|edit|patch)[-_]?(tool|prompt|system|instruction|config|constraint|guardrail|safety)",
        re.IGNORECASE,
    ),
    re.compile(r"(redefine|rewrite|overwrite)[-_]?(self|tool|definition|schema)", re.IGNORECASE),
    re.compile(
        r"(disable|remove|bypass)[-_]?(safety|guardrail|constraint|filter|limit)", re.IGNORECASE
    ),
    re.compile(r"self[-_]?(update|modify|patch|configure|rewrite)", re.IGNORECASE),
]


class AgentSelfModificationCheck(BaseCheck):
    """Agent Self-Modification."""

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
            combined = f"{tool.get('name', '')} {tool.get('description', '')}"
            matched = [p.pattern for p in SELF_MODIFY_PATTERNS if p.search(combined)]
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
                            f"Tool '{tool_name}' may allow self-modification of agent "
                            f"definitions or constraints: '{matched[0]}'"
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
                    status_extended="No agent self-modification tool patterns detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
