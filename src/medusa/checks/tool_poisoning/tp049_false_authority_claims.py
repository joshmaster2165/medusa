"""TP049: False Authority Claims.

Detects false authority or endorsement claims in tool descriptions such as
"admin-approved", "security-team recommended", or "officially endorsed" that
assert legitimacy but cannot be verified through MCP metadata alone.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_AUTHORITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(admin|administrator)[-\s]?"
            r"(approved|verified|endorsed|certified)",
            re.IGNORECASE,
        ),
        "admin endorsement",
    ),
    (
        re.compile(
            r"(security|infosec)[-\s]?team[-\s]?"
            r"(recommended|approved|verified)",
            re.IGNORECASE,
        ),
        "security team claim",
    ),
    (
        re.compile(
            r"(officially|formally)[-\s]?"
            r"(endorsed|approved|certified|sanctioned)",
            re.IGNORECASE,
        ),
        "official endorsement",
    ),
    (
        re.compile(
            r"(company|corporate|org)[-\s]?"
            r"(verified|approved|sanctioned)",
            re.IGNORECASE,
        ),
        "org endorsement",
    ),
    (
        re.compile(
            r"(compliance|audit)[-\s]?"
            r"(approved|certified|passed)",
            re.IGNORECASE,
        ),
        "compliance claim",
    ),
    (
        re.compile(
            r"(SOC\s*2|ISO\s*27001|HIPAA|PCI|GDPR)[-\s]?"
            r"(certified|compliant|approved)",
            re.IGNORECASE,
        ),
        "certification claim",
    ),
]


class FalseAuthorityClaimsCheck(BaseCheck):
    """False Authority Claims."""

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

            for pattern, label in _AUTHORITY_PATTERNS:
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
                            f"unverifiable authority claims: "
                            f"{', '.join(matched_labels)}. Authority "
                            f"claims in MCP tool metadata cannot be "
                            f"verified and may indicate manipulation."
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
                        f"No false authority claims detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
