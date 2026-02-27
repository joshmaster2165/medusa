"""SHADOW005: Suspicious Server Origin.

Detects MCP servers launched from suspicious origins such as temporary directories, raw IP
addresses, non-standard ports, or unverified GitHub URLs that may indicate an attacker-controlled
server.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SUSPICIOUS_PATTERNS = [
    re.compile(r"/tmp/", re.IGNORECASE),
    re.compile(r"\\temp\\", re.IGNORECASE),
    re.compile(r"raw\.githubusercontent\.com", re.IGNORECASE),
    re.compile(r"pastebin\.com", re.IGNORECASE),
    re.compile(r"https?://\d+\.\d+\.\d+\.\d+", re.IGNORECASE),
    re.compile(r":\d{5,}", re.IGNORECASE),  # Non-standard high port
]


class SuspiciousServerOriginCheck(BaseCheck):
    """Suspicious Server Origin."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        surfaces = [snapshot.command or "", snapshot.transport_url or ""] + list(snapshot.args)
        combined = " ".join(surfaces)

        if not combined.strip():
            return findings

        for pat in _SUSPICIOUS_PATTERNS:
            m = pat.search(combined)
            if m:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="server",
                        resource_name=snapshot.server_name,
                        status_extended=f"Suspicious server origin detected: {m.group()}",
                        evidence=f"match={m.group()}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
                break  # One finding per server is enough

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
                    status_extended="No suspicious server origin indicators detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
