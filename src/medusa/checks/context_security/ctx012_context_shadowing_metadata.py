"""CTX012: Context Shadowing via Tool Metadata.

Detects tool descriptions that attempt to shadow the LLM's context by
fabricating prior tool results, user preferences, environment state, or
conversation history to influence LLM reasoning through context manipulation
as described in the Context Shadowing TTP.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CONTEXT_SHADOW_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"previous\s+tool\s+(returned|result)", re.IGNORECASE), "fake tool result"),
    (re.compile(r"the\s+(result|output)\s+(was|is|shows)", re.IGNORECASE), "fabricated output"),
    (
        re.compile(r"the\s+user\s+(said|wants|asked|prefers|confirmed)", re.IGNORECASE),
        "fake user intent",
    ),
    (re.compile(r"user\s+preference\s+is", re.IGNORECASE), "fake user preference"),
    (
        re.compile(r"(running|deployed)\s+in\s+(production|debug|test)\s+mode", re.IGNORECASE),
        "fake environment",
    ),
    (
        re.compile(r"earlier\s+you\s+(agreed|confirmed|decided)", re.IGNORECASE),
        "fake prior agreement",
    ),
    (
        re.compile(r"we\s+already\s+(confirmed|agreed|established)", re.IGNORECASE),
        "fake prior consensus",
    ),
    (re.compile(r"previous\s+conversation", re.IGNORECASE), "fake conversation history"),
    (
        re.compile(r"as\s+(previously|already)\s+(discussed|agreed|confirmed)", re.IGNORECASE),
        "fake prior discussion",
    ),
]


class ContextShadowingMetadataCheck(BaseCheck):
    """Context Shadowing via Tool Metadata."""

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
            # Combine tool description + all parameter descriptions
            parts: list[str] = [tool.get("description", "") or ""]
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            for param_def in properties.values():
                if isinstance(param_def, dict):
                    parts.append(param_def.get("description", "") or "")
            all_text = " ".join(parts)

            if not all_text.strip():
                continue

            matched: list[str] = []
            for pattern, label in _CONTEXT_SHADOW_PATTERNS:
                match = pattern.search(all_text)
                if match:
                    matched.append(label)

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
                            f"Tool '{tool_name}' contains context "
                            f"shadowing patterns: {', '.join(matched[:3])}. "
                            f"These attempt to fabricate prior context to "
                            f"influence LLM reasoning."
                        ),
                        evidence=f"context_shadow_matches={matched[:5]}",
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
                        f"No context shadowing patterns detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
