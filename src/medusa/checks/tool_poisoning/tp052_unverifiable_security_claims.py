"""TP052: Unverifiable Security Claims.

Detects unverifiable security claims in tool descriptions such as "sanitizes
all input", "SQL injection proof", "cannot be hacked", or "100% safe". These
absolute claims cannot be verified from metadata and create false trust.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SECURITY_CLAIM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(sanitize[sd]?|filter[sd]?)\s+(all\s+)?(input|data|queries)",
            re.IGNORECASE,
        ),
        "input sanitization claim",
    ),
    (
        re.compile(
            r"(SQL|command|XSS)\s+injection\s+"
            r"(proof|safe|protected|immune)",
            re.IGNORECASE,
        ),
        "injection immunity claim",
    ),
    (
        re.compile(
            r"(end[-\s]?to[-\s]?end|fully|completely)\s+encrypted",
            re.IGNORECASE,
        ),
        "encryption claim",
    ),
    (
        re.compile(
            r"(fully|completely|100\s*%)\s+"
            r"(validated|safe|secure|protected)",
            re.IGNORECASE,
        ),
        "absolute security claim",
    ),
    (
        re.compile(
            r"\b(zero[-\s]?day|vulnerability)[-\s]?"
            r"(proof|free|immune)\b",
            re.IGNORECASE,
        ),
        "vulnerability immunity",
    ),
    (
        re.compile(
            r"\bno\s+(security\s+)?(risks?|vulnerabilities|weaknesses)\b",
            re.IGNORECASE,
        ),
        "no-risk claim",
    ),
    (
        re.compile(
            r"\bcannot\s+be\s+(hacked|compromised|exploited|breached)\b",
            re.IGNORECASE,
        ),
        "unhackable claim",
    ),
]


class UnverifiableSecurityClaimsCheck(BaseCheck):
    """Unverifiable Security Claims."""

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

            for pattern, label in _SECURITY_CLAIM_PATTERNS:
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
                            f"unverifiable security claims: "
                            f"{', '.join(matched_labels)}. Absolute "
                            f"security claims cannot be verified from "
                            f"metadata and create false trust."
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
                        f"No unverifiable security claims detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
