"""TP026: Description Length Anomaly.

Detects tool descriptions exceeding 3000 characters. Excessively long descriptions
may hide prompt injection payloads in text the user or LLM won't fully read,
burying malicious instructions deep within verbose prose.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Absolute threshold: descriptions longer than this are suspicious.
_ABSOLUTE_THRESHOLD = 3000

# Relative threshold: descriptions >5x the average are suspicious.
_RELATIVE_MULTIPLIER = 5


class DescriptionLengthAnomalyCheck(BaseCheck):
    """Description Length Anomaly."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Compute the average description length across all tools.
        descriptions = [
            tool.get("description", "") or "" for tool in snapshot.tools
        ]
        lengths = [len(d) for d in descriptions]
        avg_length = sum(lengths) / len(lengths) if lengths else 0

        for tool, desc, length in zip(snapshot.tools, descriptions, lengths):
            tool_name: str = tool.get("name", "<unnamed>")
            issues: list[str] = []

            # Check 1: absolute threshold
            if length > _ABSOLUTE_THRESHOLD:
                issues.append(
                    f"description is {length} chars (threshold: {_ABSOLUTE_THRESHOLD})"
                )

            # Check 2: relative anomaly (>5x average)
            if avg_length > 0 and length > avg_length * _RELATIVE_MULTIPLIER:
                issues.append(
                    f"description is {length} chars, "
                    f"{length / avg_length:.1f}x the average of {avg_length:.0f} chars"
                )

            if issues:
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
                            f"Tool '{tool_name}' has an anomalously long description: "
                            f"{'; '.join(issues)}. Long descriptions may conceal "
                            f"prompt injection payloads."
                        ),
                        evidence=f"length={length}, avg={avg_length:.0f}",
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
                    status_extended=(
                        f"No description length anomalies detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
