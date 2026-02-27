"""SHADOW006: Server Version Spoofing.

Detects MCP servers with suspicious version numbers that may indicate version spoofing. Spoofed
versions can trick clients into trusting malicious servers masquerading as known-good versions.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SUSPICIOUS_VERSIONS = [
    re.compile(r"^0\.0\.0$"),
    re.compile(r"^999\."),
    re.compile(r"^9{3,}\."),
    re.compile(r"^(test|fake|dev|hack|evil)"),
    re.compile(r"^0\.0\.1-.*"),
]


class ServerVersionSpoofingCheck(BaseCheck):
    """Server Version Spoofing."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        info = snapshot.server_info or {}
        version = info.get("version", "")
        if not version:
            return findings

        for pat in _SUSPICIOUS_VERSIONS:
            if pat.search(version):
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
                        status_extended=f"Suspicious server version: '{version}'",
                        evidence=f"version={version}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
                break

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
                    status_extended=f"Server version '{version}' appears legitimate.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
