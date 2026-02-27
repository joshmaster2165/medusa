"""INTG015: Binary Planting Risk.

Detects MCP servers launched from writable or temporary directories where attackers could plant
malicious binaries. Executables in /tmp, user-writable paths, or download directories are suspect.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_RISKY_PREFIXES = ["/tmp", "/var/tmp", "/dev/shm", "C:\\Temp", "C:\\Windows\\Temp"]
_RISKY_SUBSTRINGS = ["downloads", "desktop", ".cache", "temp", "tmp"]


class BinaryPlantingRiskCheck(BaseCheck):
    """Binary Planting Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.command:
            return findings

        cmd = snapshot.command
        cmd_lower = cmd.lower()

        risky = False
        reason = ""
        for prefix in _RISKY_PREFIXES:
            if cmd_lower.startswith(prefix.lower()):
                risky = True
                reason = f"command in risky prefix: {prefix}"
                break
        if not risky:
            for sub in _RISKY_SUBSTRINGS:
                if sub in cmd_lower:
                    risky = True
                    reason = f"command path contains: {sub}"
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
                    status_extended=f"Binary planting risk: {reason}",
                    evidence=f"command={cmd}",
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
                    status_extended="Command path does not indicate binary planting risk.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
