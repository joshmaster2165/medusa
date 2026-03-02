"""SC009: Writable Directory Binary Path.

Detects when the MCP server command binary is located in a world-writable or
temporary directory. An attacker with local access can replace the binary in
these directories to achieve arbitrary code execution under the MCP server's
privileges.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Known writable / temporary directory prefixes (POSIX and common patterns).
_WRITABLE_PREFIXES: tuple[str, ...] = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
)

# Patterns that indicate a writable / temporary path segment.
_WRITABLE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[/\\]\.tmp[/\\]?", re.IGNORECASE),
    re.compile(r"[/\\]temp[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]Downloads[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]Desktop[/\\]", re.IGNORECASE),
]


def _is_writable_path(command: str) -> tuple[bool, str]:
    """Check if a command path is in a writable/temp directory.

    Returns (is_writable, reason).
    """
    # Normalise to forward slashes for cross-platform matching.
    normalised = command.replace("\\", "/")

    # Check known writable prefixes.
    for prefix in _WRITABLE_PREFIXES:
        if normalised.startswith(prefix):
            return True, f"path starts with '{prefix}'"

    # Check for writable path patterns.
    for pattern in _WRITABLE_PATTERNS:
        match = pattern.search(command)
        if match:
            return True, f"path contains writable segment '{match.group(0).strip(os.sep)}'"

    return False, ""


class WritableBinaryPathCheck(BaseCheck):
    """Writable Directory Binary Path."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Only applicable to stdio transport with a command.
        if snapshot.transport_type != "stdio" or not snapshot.command:
            return findings

        is_writable, reason = _is_writable_path(snapshot.command)

        if is_writable:
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
                        f"Server '{snapshot.server_name}' command binary is in a "
                        f"writable/temporary directory ({reason}): "
                        f"'{snapshot.command}'. An attacker could replace the binary "
                        f"to achieve code execution."
                    ),
                    evidence=f"command={snapshot.command}, reason={reason}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

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
                    status_extended=(
                        f"Server '{snapshot.server_name}' command binary is not in "
                        f"a writable or temporary directory."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
