"""TP055: Official/Certification Claims.

Detects "official", "certified", "authorized", or "licensed" claims in tool
metadata that assert legitimacy but cannot be verified through MCP metadata
alone. These are commonly used in tool impersonation attacks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CERTIFICATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\bofficial\s+(integration|connector|plugin|tool|api)\b",
            re.IGNORECASE,
        ),
        "official claim",
    ),
    (
        re.compile(
            r"\bcertified\s+(by|integration|connector|partner)\b",
            re.IGNORECASE,
        ),
        "certification claim",
    ),
    (
        re.compile(
            r"\bauthorized\s+(by|partner|reseller|distributor)\b",
            re.IGNORECASE,
        ),
        "authorization claim",
    ),
    (
        re.compile(
            r"\blicensed\s+(by|from|partner)\b",
            re.IGNORECASE,
        ),
        "license claim",
    ),
    (
        re.compile(
            r"\bpartner\s+(integration|certified|verified)\b",
            re.IGNORECASE,
        ),
        "partner claim",
    ),
    (
        re.compile(
            r"\bverified\s+(by|publisher|developer|vendor)\b",
            re.IGNORECASE,
        ),
        "verification claim",
    ),
]


class OfficialCertificationClaimsCheck(BaseCheck):
    """Official/Certification Claims."""

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

            for pattern, label in _CERTIFICATION_PATTERNS:
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
                            f"unverifiable certification/official claims: "
                            f"{', '.join(matched_labels)}. These claims "
                            f"cannot be verified through MCP metadata."
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
                        f"No official/certification claims detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
