"""INTG-003: Configuration Stored in World-Writable Path.

Detects MCP server configurations stored in temporary or world-writable
directories where any local user or process could modify them.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Directories considered world-writable / risky.
_RISKY_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/tmp",
    "/var/tmp/",
    "/var/tmp",
    "/dev/shm/",
    "/dev/shm",
)

_RISKY_SUBSTRINGS: tuple[str, ...] = (
    "/temp/",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


def _is_risky_path(path: str) -> bool:
    """Return True if the path is in a world-writable or temp directory."""
    normalised = path.lower().replace("\\", "/")

    # Check prefixes.
    for prefix in _RISKY_PREFIXES:
        if prefix.endswith("/"):
            if normalised.startswith(prefix):
                return True
        else:
            if normalised == prefix or normalised.startswith(prefix + "/"):
                    return True

    # Check substrings for embedded temp directories.
    for substr in _RISKY_SUBSTRINGS:
        if substr in normalised:
            return True

    return False


class ConfigTamperingRiskCheck(BaseCheck):
    """Check for configuration files stored in world-writable paths."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Skip if no config file path is available.
        if not snapshot.config_file_path:
            return findings

        if _is_risky_path(snapshot.config_file_path):
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
                    status_extended=(
                        f"Server '{snapshot.server_name}' configuration is "
                        f"stored at '{snapshot.config_file_path}', which is in "
                        f"a world-writable or temporary directory. Any local "
                        f"user or process can modify this configuration."
                    ),
                    evidence=f"config_file_path={snapshot.config_file_path}",
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
                    status_extended=(
                        f"Server '{snapshot.server_name}' configuration at "
                        f"'{snapshot.config_file_path}' is not in a "
                        f"world-writable directory."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
