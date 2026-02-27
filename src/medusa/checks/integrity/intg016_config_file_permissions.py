"""INTG016: Insecure Configuration File Location.

Detects MCP server configuration files stored in world-readable, shared, or temporary locations
where unauthorized users could modify them. Configuration tampering enables privilege escalation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_RISKY_LOCATIONS = ["/tmp", "/var/tmp", "/dev/shm", "/shared", "/public"]


class ConfigFilePermissionsCheck(BaseCheck):
    """Insecure Configuration File Location."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.config_file_path:
            return findings

        cfg_path = snapshot.config_file_path.lower()
        risky = False
        for loc in _RISKY_LOCATIONS:
            if cfg_path.startswith(loc):
                risky = True
                break

        if risky:
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
                    status_extended=f"Config file in risky location: {snapshot.config_file_path}",
                    evidence=f"config_path={snapshot.config_file_path}",
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
                    status_extended="Config file location appears secure.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
