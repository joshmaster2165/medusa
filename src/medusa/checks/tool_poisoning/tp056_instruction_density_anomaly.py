"""TP056: Instruction Density Anomaly.

Detects tool descriptions with abnormally high instruction density — a high
ratio of imperative/directive language relative to descriptive language.
Normal descriptions describe what a tool does; poisoned descriptions are
dense with instructions directing the LLM.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_IMPERATIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(must|shall|should|always|never|ensure|require|do\s+not)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(execute|perform|invoke|call|send|forward|transmit)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(immediately|first|before|after|prior\s+to)\b",
        re.IGNORECASE,
    ),
]

# Minimum thresholds to reduce false positives
_MIN_WORD_COUNT = 10
_MIN_IMPERATIVE_COUNT = 5
_MAX_DENSITY = 0.15


class InstructionDensityAnomalyCheck(BaseCheck):
    """Instruction Density Anomaly."""

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

            words = description.split()
            word_count = len(words)

            if word_count < _MIN_WORD_COUNT:
                continue

            imperative_count = sum(len(p.findall(description)) for p in _IMPERATIVE_PATTERNS)
            density = imperative_count / word_count

            if density > _MAX_DENSITY and imperative_count >= _MIN_IMPERATIVE_COUNT:
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
                            f"Tool '{tool_name}' description has "
                            f"abnormally high instruction density: "
                            f"{density:.1%} ({imperative_count} "
                            f"directives in {word_count} words). "
                            f"Normal descriptions have <5% imperative "
                            f"density."
                        ),
                        evidence=(
                            f"density={density:.2%}, "
                            f"imperative_count={imperative_count}, "
                            f"word_count={word_count}"
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
                        f"No instruction density anomalies detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
