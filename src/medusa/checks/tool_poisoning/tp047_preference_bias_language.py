"""TP047: Preference Bias Language.

Detects persuasive or biased language in tool descriptions designed to
manipulate LLM tool selection — superlatives, selection directives, and
unverifiable trust claims. Requires 2+ different bias categories to reduce
false positives.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_PREFERENCE_BIAS_PATTERNS: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "superlative": [
        (
            re.compile(
                r"\b(best|safest|most\s+secure|most\s+reliable|superior)\b",
                re.IGNORECASE,
            ),
            "superlative claim",
        ),
    ],
    "selection_directive": [
        (
            re.compile(
                r"\b(always\s+use|first\s+choice|go-to|preferred)\b",
                re.IGNORECASE,
            ),
            "selection directive",
        ),
        (
            re.compile(
                r"(should|must)\s+(always\s+)?(be\s+)?"
                r"(selected|chosen|used|preferred)",
                re.IGNORECASE,
            ),
            "selection mandate",
        ),
    ],
    "trust_claim": [
        (
            re.compile(
                r"\b(verified|trusted|guaranteed|proven|battle-tested)\b",
                re.IGNORECASE,
            ),
            "trust claim",
        ),
    ],
    "endorsement": [
        (
            re.compile(
                r"\b(recommended|endorsed|approved)\s+"
                r"(tool|option|choice)\b",
                re.IGNORECASE,
            ),
            "endorsement claim",
        ),
    ],
}


class PreferenceBiasLanguageCheck(BaseCheck):
    """Preference Bias Language."""

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

            matched_categories: set[str] = set()
            matched_labels: list[str] = []

            for category, patterns in _PREFERENCE_BIAS_PATTERNS.items():
                for pattern, label in patterns:
                    if pattern.search(description):
                        matched_categories.add(category)
                        matched_labels.append(label)
                        break  # One match per category is enough

            # Require 2+ different bias categories to reduce FP
            if len(matched_categories) >= 2:
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
                            f"preference bias language across "
                            f"{len(matched_categories)} categories: "
                            f"{', '.join(matched_labels)}. This may "
                            f"manipulate LLM tool selection."
                        ),
                        evidence=(
                            f"categories={sorted(matched_categories)}, labels={matched_labels}"
                        ),
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
                        f"No preference bias language detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
