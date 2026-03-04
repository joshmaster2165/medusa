"""TP033: Conditional Behavior in Tool Descriptions.

Detects tool descriptions containing conditional or branching language
that suggests the tool behaves differently based on context, role, or
environment. This is an indicator of the Tool Mutation / Rug Pull TTP
where tools activate hidden behaviour under specific conditions.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CONDITIONAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\bif\s+(you\s+are|the\s+user\s+(is|has)|admin|authenticated|authorized)",
            re.IGNORECASE,
        ),
        "role-conditional",
    ),
    (
        re.compile(
            r"\bwhen\s+(in\s+(debug|admin|production|dev)|running\s+as)",
            re.IGNORECASE,
        ),
        "mode-conditional",
    ),
    (
        re.compile(
            r"\bdepending\s+on\s+(the\s+)?(role|context|mode|environment|permission)",
            re.IGNORECASE,
        ),
        "context-dependent",
    ),
    (
        re.compile(
            r"\bin\s+(production|development|debug|admin|test)\s+mode",
            re.IGNORECASE,
        ),
        "mode-specific",
    ),
    (
        re.compile(
            r"\bafter\s+(authentication|login|first\s+run|initialization)",
            re.IGNORECASE,
        ),
        "time-conditional",
    ),
    (
        re.compile(
            r"\bonly\s+(when|if|for)\s+(admin|root|superuser|authorized)",
            re.IGNORECASE,
        ),
        "privilege-gated",
    ),
    (
        re.compile(
            r"\bunless\s+(admin|authorized|permitted|approved)",
            re.IGNORECASE,
        ),
        "inverse-gate",
    ),
    (
        re.compile(
            r"\bbased\s+on\s+(user|role|permission|context|environment)",
            re.IGNORECASE,
        ),
        "context-switch",
    ),
]


class ConditionalBehaviorDescriptionCheck(BaseCheck):
    """Conditional Behavior in Tool Descriptions."""

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
            description: str = tool.get("description", "") or ""

            if not description:
                continue

            matched: list[str] = []
            for pattern, label in _CONDITIONAL_PATTERNS:
                if pattern.search(description):
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
                            f"Tool '{tool_name}' description contains "
                            f"conditional behavior patterns: "
                            f"{', '.join(matched)}. This suggests "
                            f"context-dependent behavior changes."
                        ),
                        evidence=f"conditional_patterns={matched}",
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
                        f"No conditional behavior patterns detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
