"""TP050: Conditional Tool Selection Directive.

Detects conditional selection instructions embedded in tool descriptions that
manipulate the LLM's tool selection — "if unsure, use this tool", "when in
doubt", "should be your first choice", "default to this".
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SELECTION_DIRECTIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"if\s+(unsure|uncertain|in\s+doubt).*use\s+this",
            re.IGNORECASE,
        ),
        "uncertainty exploitation",
    ),
    (
        re.compile(
            r"(should|must)\s+be\s+(your\s+)?"
            r"(first|default|primary)\s+(choice|option|tool)",
            re.IGNORECASE,
        ),
        "priority claim",
    ),
    (
        re.compile(
            r"(default|fallback)\s+to\s+this\s+tool",
            re.IGNORECASE,
        ),
        "default claim",
    ),
    (
        re.compile(
            r"(always|automatically)\s+(select|choose|pick|use)\s+this",
            re.IGNORECASE,
        ),
        "auto-selection",
    ),
    (
        re.compile(
            r"(prefer|prioritize)\s+this\s+(over|above|before)\s+"
            r"(other|alternative)",
            re.IGNORECASE,
        ),
        "priority override",
    ),
    (
        re.compile(
            r"use\s+this\s+(tool\s+)?"
            r"(whenever|any\s*time|every\s*time)",
            re.IGNORECASE,
        ),
        "universal selection",
    ),
    (
        re.compile(
            r"no\s+need\s+to\s+(check|verify|validate|confirm)",
            re.IGNORECASE,
        ),
        "validation bypass",
    ),
]


class ConditionalToolSelectionDirectiveCheck(BaseCheck):
    """Conditional Tool Selection Directive."""

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

            if not description:
                continue

            matched_labels: list[str] = []
            matched_snippets: list[str] = []

            for pattern, label in _SELECTION_DIRECTIVE_PATTERNS:
                m = pattern.search(description)
                if m:
                    matched_labels.append(label)
                    snippet = m.group()
                    truncated = snippet[:80] + "..." if len(snippet) > 80 else snippet
                    matched_snippets.append(truncated)

            if matched_labels:
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
                            f"Tool '{tool_name}' description contains "
                            f"selection directives that manipulate "
                            f"LLM tool choice: "
                            f"{', '.join(matched_labels)}."
                        ),
                        evidence=(f"matches=[{'; '.join(matched_snippets)}]"),
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
                        f"No conditional selection directives detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
