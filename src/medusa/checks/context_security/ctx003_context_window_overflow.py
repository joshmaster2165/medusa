"""CTX003: Context Window Overflow Attack.

Detects MCP tool outputs or resource contents designed to flood the LLM context window with
excessive data. Context window overflow attacks push legitimate instructions out of the context,
causing the LLM to lose track of its original directives.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# 100k chars is roughly 25k tokens — a significant fraction of most context windows
_TOTAL_CHAR_THRESHOLD = 100_000
# Per-item thresholds
_ITEM_CHAR_THRESHOLD = 10_000


class ContextWindowOverflowCheck(BaseCheck):
    """Context Window Overflow Attack."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        total_chars = 0
        large_items: list[str] = []

        # Sum all tool descriptions
        for tool in snapshot.tools:
            desc = tool.get("description") or ""
            total_chars += len(desc)
            if len(desc) > _ITEM_CHAR_THRESHOLD:
                large_items.append(f"tool '{tool.get('name', '?')}' ({len(desc)} chars)")

        # Sum all resource descriptions
        for res in snapshot.resources:
            desc = res.get("description") or ""
            total_chars += len(desc)
            if len(desc) > _ITEM_CHAR_THRESHOLD:
                large_items.append(f"resource '{res.get('name', '?')}' ({len(desc)} chars)")

        # Sum all prompt descriptions
        for prompt in snapshot.prompts:
            desc = prompt.get("description") or ""
            total_chars += len(desc)

        if total_chars > _TOTAL_CHAR_THRESHOLD or large_items:
            details = (
                f"Total description content: {total_chars:,} chars. "
                f"Large items: {', '.join(large_items[:5]) or 'none'}"
            )
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' has excessive description content "
                        f"({total_chars:,} chars). This may flood the LLM context window."
                    ),
                    evidence=details,
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                        f"Total description content ({total_chars:,} chars) is within "
                        f"acceptable limits for context window usage."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
