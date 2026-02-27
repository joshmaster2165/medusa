"""PMT014: Prompt History Manipulation.

Detects MCP prompt definitions that reference or instruct manipulation of
conversation history — injecting fake prior messages or altering context to
socially engineer the LLM.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HISTORY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"conversation\s+history\b", re.IGNORECASE),
    re.compile(r"previous\s+messages?\b", re.IGNORECASE),
    re.compile(r"chat\s+history\b", re.IGNORECASE),
    re.compile(r"inject\s+(?:a\s+)?(?:fake|previous|prior)\b", re.IGNORECASE),
    re.compile(r"prepend\s+(?:to\s+)?(?:the\s+)?(?:history|context)\b", re.IGNORECASE),
    re.compile(r"alter\s+(?:the\s+)?(?:history|context|conversation)\b", re.IGNORECASE),
    re.compile(r"forge\s+(?:a\s+)?message\b", re.IGNORECASE),
    re.compile(r"fabricat(?:e|ed)\s+(?:context|history|message)\b", re.IGNORECASE),
    re.compile(r"as\s+(?:if\s+)?(?:the\s+)?user\s+(?:previously\s+)?said\b", re.IGNORECASE),
]


class PromptHistoryManipulationCheck(BaseCheck):
    """Prompt History Manipulation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.prompts:
            return findings

        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "<unnamed>")
            description = prompt.get("description", "")

            hits: list[str] = []
            for pattern in _HISTORY_PATTERNS:
                for m in pattern.finditer(description):
                    hits.append(m.group()[:100])

            if hits:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="prompt",
                        resource_name=prompt_name,
                        status_extended=(
                            f"Prompt '{prompt_name}' contains conversation "
                            f"history manipulation patterns: "
                            f"{'; '.join(hits[:3])}"
                        ),
                        evidence="; ".join(hits[:5]),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.prompts:
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
                        f"No history manipulation patterns detected across "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
