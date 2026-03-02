"""TP-002: Detect prompt injection phrases in MCP tool descriptions.

Scans every tool description and parameter description for explicit prompt
injection phrases such as "ignore previous instructions", "do not tell the
user", "secretly", and other patterns defined in the pattern-matching module.

Uses context-aware scoring to reduce false positives — phrases that appear
in documentation/example context or are preceded by negation words (e.g.
"this tool prevents users from ignoring instructions") are down-weighted.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status
from medusa.utils.heuristics import score_injection_context
from medusa.utils.text_analysis import find_injection_phrases

# Matches with a context score below this threshold are treated as
# false positives (documentation, examples, negation context, etc.).
_CONTEXT_SCORE_THRESHOLD = 0.5


class PromptInjectionCheck(BaseCheck):
    """Check for prompt injection phrases in tool descriptions."""

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

            # Collect all text surfaces to scan: description + param descriptions
            text_surfaces: list[tuple[str, str]] = []
            if description:
                text_surfaces.append(("description", description))

            input_schema = tool.get("inputSchema", {})
            schema_properties = input_schema.get("properties", {})
            for param_name, param_def in schema_properties.items():
                param_desc: str = param_def.get("description", "")
                if param_desc:
                    text_surfaces.append((f"parameter '{param_name}' description", param_desc))

            for surface_label, text in text_surfaces:
                injection_matches = find_injection_phrases(text)
                if not injection_matches:
                    continue

                # Deduplicate while preserving order
                unique_phrases = list(dict.fromkeys(injection_matches))

                # Score each match in context to filter false positives
                confirmed: list[tuple[str, float]] = []
                text_lower = text.lower()
                for phrase in unique_phrases:
                    start = text_lower.find(phrase.lower())
                    if start == -1:
                        # Fallback: phrase came from regex, treat as confirmed
                        confirmed.append((phrase, 1.0))
                        continue
                    ctx_score = score_injection_context(text, start, start + len(phrase))
                    if ctx_score >= _CONTEXT_SCORE_THRESHOLD:
                        confirmed.append((phrase, ctx_score))

                if not confirmed:
                    continue  # All matches were false positives

                phrases_only = [p for p, _ in confirmed]
                scores_only = [s for _, s in confirmed]
                avg_score = sum(scores_only) / len(scores_only)
                phrase_list = ", ".join(f"'{p}'" for p in phrases_only[:5])

                # Downgrade severity for borderline matches
                severity = meta.severity
                if avg_score < 0.8:
                    severity = Severity.MEDIUM

                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' {surface_label} contains "
                            f"prompt injection phrase(s): {phrase_list}"
                        ),
                        evidence=(
                            "; ".join(phrases_only[:10]) + f" [avg_context_score={avg_score:.2f}]"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Emit PASS if no injection phrases were found
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
                        f"No prompt injection phrases detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
