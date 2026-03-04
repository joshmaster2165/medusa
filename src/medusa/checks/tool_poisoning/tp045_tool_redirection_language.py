"""TP045: Tool Redirection Language.

Detects tool descriptions that explicitly redirect the LLM away from other
tools — e.g., "instead of X", "replaces X", "improved version of X". This
is a direct indicator of tool shadowing attacks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_REDIRECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(instead\s+of|replace[sd]?|supersede[sd]?)\s+['\"]?\w+",
            re.IGNORECASE,
        ),
        "tool replacement claim",
    ),
    (
        re.compile(
            r"(improved|better|enhanced|safer)\s+version\s+of\s+\w+",
            re.IGNORECASE,
        ),
        "version superiority claim",
    ),
    (
        re.compile(
            r"use\s+this\s+(instead|rather\s+than|not)\s+",
            re.IGNORECASE,
        ),
        "explicit redirection",
    ),
    (
        re.compile(
            r"(deprecated|obsolete|legacy).*use\s+this",
            re.IGNORECASE,
        ),
        "deprecation redirect",
    ),
    (
        re.compile(
            r"do\s+not\s+use\s+['\"]?\w+['\"]?.*use\s+this",
            re.IGNORECASE,
        ),
        "anti-tool directive",
    ),
    (
        re.compile(
            r"prefer\s+this\s+(tool|over)\b",
            re.IGNORECASE,
        ),
        "preference override",
    ),
]


class ToolRedirectionLanguageCheck(BaseCheck):
    """Tool Redirection Language."""

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

            for pattern, label in _REDIRECTION_PATTERNS:
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
                            f"redirection language that attempts to "
                            f"shadow or replace other tools: "
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
                        f"No tool redirection language detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
