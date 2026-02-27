"""INTG-002: Unsigned Server Binaries.

Detects MCP servers that run local script files (node script.js, python
script.py) without any integrity verification keys in the server
configuration.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Interpreters that execute local scripts.
_SCRIPT_RUNNERS: set[str] = {"node", "python", "python3", "ruby", "deno", "bun"}

# File extensions that indicate a local script.
_SCRIPT_EXTENSIONS: re.Pattern[str] = re.compile(r"\.(js|mjs|cjs|ts|py|rb|sh|bash)$", re.IGNORECASE)

# Config keys indicating integrity verification is in place.
_INTEGRITY_KEYS: set[str] = {
    "hash",
    "checksum",
    "integrity",
    "sha256",
    "sha512",
    "signature",
    "sig",
    "digest",
}


def _runs_local_script(command: str | None, args: list[str]) -> tuple[bool, str]:
    """Return (True, script_path) if the command runs a local script file."""
    if not command:
        return False, ""

    command_base = Path(command).name.lower()

    if command_base not in _SCRIPT_RUNNERS:
        return False, ""

    for arg in args:
        if not arg.startswith("-") and _SCRIPT_EXTENSIONS.search(arg):
            return True, arg

    return False, ""


def _config_has_integrity(config: dict | None) -> bool:
    """Check if the config contains any integrity verification keys."""
    if not config:
        return False

    def _search(d: dict) -> bool:
        for key, value in d.items():
            if key.lower() in _INTEGRITY_KEYS:
                return True
            if isinstance(value, dict) and _search(value):
                return True
        return False

    return _search(config)


class UnsignedServerBinariesCheck(BaseCheck):
    """Check for local scripts running without integrity verification."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Only applicable to stdio transport.
        if snapshot.transport_type != "stdio":
            return findings

        is_script, script_path = _runs_local_script(snapshot.command, snapshot.args)

        if not is_script:
            return findings

        has_integrity = _config_has_integrity(snapshot.config_raw)

        if has_integrity:
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
                        f"Server '{snapshot.server_name}' runs local script "
                        f"'{script_path}' with integrity verification configured."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                        f"Server '{snapshot.server_name}' runs local script "
                        f"'{script_path}' without integrity verification. "
                        f"A tampered script will execute without detection."
                    ),
                    evidence=(
                        f"command={snapshot.command}, "
                        f"script={script_path}, "
                        f"no integrity keys in config"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
