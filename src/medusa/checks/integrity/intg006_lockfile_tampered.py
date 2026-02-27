"""INTG006: Lockfile Integrity Bypass.

Detects MCP server launch configurations that include flags to skip lockfile integrity checks,
such as --no-frozen-lockfile or --no-immutable, which defeat the purpose of having a lockfile.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_BYPASS_FLAGS = {
    "--no-frozen-lockfile",
    "--no-immutable",
    "--ignore-lockfile",
    "--no-lock",
    "--skip-lock",
    "--force",
}


class LockfileTamperedCheck(BaseCheck):
    """Lockfile Integrity Bypass."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type != "stdio" or not snapshot.command:
            return findings

        all_args = list(snapshot.args)
        found_flags = [a for a in all_args if a.lower() in _BYPASS_FLAGS]

        if found_flags:
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
                    status_extended=f"Lockfile bypass flags detected: {', '.join(found_flags)}",
                    evidence=f"flags={', '.join(found_flags)}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                    status_extended="No lockfile bypass flags detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
