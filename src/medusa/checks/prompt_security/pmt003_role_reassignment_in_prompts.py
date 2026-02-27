"""PMT003: Role Reassignment in Prompts.

Detects MCP prompt definitions that attempt to reassign the LLM role, override system
instructions, or establish new behavioral constraints. Prompts containing phrases like "you are
now" or "ignore previous instructions" can manipulate LLM identity.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_ROLE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"act\s+as\b", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"pretend\s+to\s+be\b", re.IGNORECASE),
    re.compile(r"from\s+now\s+on\s+you\s+are\b", re.IGNORECASE),
    re.compile(r"your\s+new\s+role\b", re.IGNORECASE),
    re.compile(r"you\s+will\s+now\s+act\b", re.IGNORECASE),
    re.compile(r"assume\s+the\s+role\b", re.IGNORECASE),
]


class RoleReassignmentInPromptsCheck(BaseCheck):
    """Role Reassignment in Prompts."""

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
            for pattern in _ROLE_PATTERNS:
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
                            f"Prompt '{prompt_name}' contains role-reassignment "
                            f"phrases: {'; '.join(hits[:3])}"
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
                        f"No role reassignment phrases detected across "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
