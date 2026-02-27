"""CTX009: Role Confusion Attack.

Detects MCP tool outputs containing content designed to confuse the LLM's understanding of
message roles (system, user, assistant, tool). Role confusion can trick the LLM into treating
tool output as system instructions.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_ROLE_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\bSystem\s*:", re.IGNORECASE),
    re.compile(r"\bAssistant\s*:", re.IGNORECASE),
    re.compile(r"\bUser\s*:", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"\[/INST\]", re.IGNORECASE),
    re.compile(r"###\s+Human\s*:", re.IGNORECASE),
    re.compile(r"###\s+Assistant\s*:", re.IGNORECASE),
    re.compile(r"<\|system\|>", re.IGNORECASE),
    re.compile(r"<\|user\|>", re.IGNORECASE),
    re.compile(r"<\|assistant\|>", re.IGNORECASE),
]


def _find_role_markers(text: str) -> list[str]:
    """Return list of role marker strings found in text."""
    hits: list[str] = []
    for pat in _ROLE_MARKERS:
        if pat.search(text):
            hits.append(pat.pattern)
    return hits


class RoleConfusionAttackCheck(BaseCheck):
    """Role Confusion Attack."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        has_content = bool(snapshot.tools or snapshot.prompts)
        if not has_content:
            return findings

        # Scan tool descriptions
        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            desc = tool.get("description") or ""
            markers = _find_role_markers(desc)
            if markers:
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
                            f"Tool '{tool_name}' description contains role-switching "
                            f"markers that may confuse the LLM."
                        ),
                        evidence=f"markers={', '.join(markers[:3])}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Scan prompt descriptions
        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "<unnamed>")
            desc = prompt.get("description") or ""
            markers = _find_role_markers(desc)
            if markers:
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
                            f"Prompt '{prompt_name}' description contains role-switching "
                            f"markers that may confuse the LLM."
                        ),
                        evidence=f"markers={', '.join(markers[:3])}",
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
                    status_extended="No role confusion markers detected in tool or prompt"
                    "descriptions.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
