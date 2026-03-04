"""TP048: Urgency Manipulation Language.

Detects urgency or pressure language in tool descriptions designed to bypass
careful evaluation by the LLM — "immediately", "emergency", "must act now",
"skip validation".
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_URGENCY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(immediately|urgently|right\s+away|without\s+delay)\b",
            re.IGNORECASE,
        ),
        "immediacy pressure",
    ),
    (
        re.compile(
            r"\b(emergency|time-sensitive|time-critical)\b",
            re.IGNORECASE,
        ),
        "emergency framing",
    ),
    (
        re.compile(
            r"\bmust\s+(act|use|respond|execute)\s+(now|immediately)\b",
            re.IGNORECASE,
        ),
        "action pressure",
    ),
    (
        re.compile(
            r"\b(do\s+not|don't)\s+(wait|delay|hesitate|pause)\b",
            re.IGNORECASE,
        ),
        "anti-deliberation",
    ),
    (
        re.compile(
            r"\b(urgent|asap|before\s+it'?s?\s+too\s+late)\b",
            re.IGNORECASE,
        ),
        "urgency signal",
    ),
    (
        re.compile(
            r"\bskip\s+(validation|verification|checking|review)\b",
            re.IGNORECASE,
        ),
        "bypass instruction",
    ),
]


class UrgencyManipulationLanguageCheck(BaseCheck):
    """Urgency Manipulation Language."""

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

            for pattern, label in _URGENCY_PATTERNS:
                m = pattern.search(description)
                if m:
                    matched_labels.append(label)
                    matched_snippets.append(m.group())

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
                            f"urgency manipulation language: "
                            f"{', '.join(matched_labels)}. This may "
                            f"pressure the LLM into bypassing careful "
                            f"evaluation."
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
                        f"No urgency manipulation language detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
