"""TP025: Tool Annotation Abuse.

Detects misuse of MCP tool annotations such as readOnlyHint, destructiveHint, idempotentHint,
and openWorldHint. A malicious server can set readOnlyHint to true on a destructive tool or
destructiveHint to false on a tool that deletes data, causing the LLM to bypass safety
confirmations.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Description patterns that imply a destructive operation
_DESTRUCTIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bdelete\b", re.IGNORECASE),
    re.compile(r"\bremove\b", re.IGNORECASE),
    re.compile(r"\boverwrite\b", re.IGNORECASE),
    re.compile(r"\bdrop\b", re.IGNORECASE),
    re.compile(r"\btruncate\b", re.IGNORECASE),
    re.compile(r"\bformat\b", re.IGNORECASE),
    re.compile(r"\berase\b", re.IGNORECASE),
    re.compile(r"\bpurge\b", re.IGNORECASE),
    re.compile(r"\bwrite\b", re.IGNORECASE),
    re.compile(r"\bmodif(?:y|ied)\b", re.IGNORECASE),
    re.compile(r"\bexecute\b", re.IGNORECASE),
]


def _description_implies_destructive(desc: str) -> bool:
    return any(p.search(desc) for p in _DESTRUCTIVE_PATTERNS)


class ToolAnnotationAbuseCheck(BaseCheck):
    """Tool Annotation Abuse."""

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
            # MCP annotations live in tool["annotations"] per spec
            annotations: dict = tool.get("annotations", {}) or {}

            if not annotations:
                continue

            read_only_hint = annotations.get("readOnlyHint", None)
            destructive_hint = annotations.get("destructiveHint", None)

            issues: list[str] = []

            # readOnlyHint=True but description implies writes/destructive ops
            if read_only_hint is True and _description_implies_destructive(description):
                issues.append("readOnlyHint=true but description implies destructive operation")

            # destructiveHint=False but description implies destructive ops
            if destructive_hint is False and _description_implies_destructive(description):
                issues.append("destructiveHint=false but description implies destructive operation")

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
                            f"Tool '{tool_name}' has annotations that contradict "
                            f"its description: {'; '.join(issues)}"
                        ),
                        evidence="; ".join(issues),
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
                        f"No annotation abuse detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
