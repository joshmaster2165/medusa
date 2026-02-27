"""CTX004: Instruction Hierarchy Violation.

Detects MCP tool outputs that contain content attempting to override or contradict system-level
instructions. Tool content should never be able to elevate its privilege above the system
prompt.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_injection_phrases

# Phrases that specifically target the instruction hierarchy / system prompt
_HIERARCHY_PHRASES = [
    "ignore your system prompt",
    "override your instructions",
    "disregard previous instructions",
    "ignore all previous",
    "your new instructions are",
    "system prompt says",
    "forget your previous",
    "new system prompt",
    "act as if your system",
    "your instructions have changed",
]


def _scan_text(text: str) -> list[str]:
    """Return matching phrases found in text."""
    lower = text.lower()
    hits = [p for p in _HIERARCHY_PHRASES if p in lower]
    hits += find_injection_phrases(text)
    return list(dict.fromkeys(hits))


class InstructionHierarchyViolationCheck(BaseCheck):
    """Instruction Hierarchy Violation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        items: list[tuple[str, str, str]] = []
        for tool in snapshot.tools:
            items.append(("tool", tool.get("name", "<unnamed>"), tool.get("description") or ""))
        for prompt in snapshot.prompts:
            items.append(
                ("prompt", prompt.get("name", "<unnamed>"), prompt.get("description") or "")
            )

        for kind, name, desc in items:
            if not desc:
                continue
            hits = _scan_text(desc)
            if hits:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type=kind,
                        resource_name=name,
                        status_extended=(
                            f"{kind.capitalize()} '{name}' contains instruction-override "
                            f"phrases that violate the system-prompt hierarchy."
                        ),
                        evidence=", ".join(repr(h) for h in hits[:5]),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and (snapshot.tools or snapshot.prompts):
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
                        f"No instruction-hierarchy-violation phrases found across "
                        f"{len(snapshot.tools)} tool(s) and {len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
