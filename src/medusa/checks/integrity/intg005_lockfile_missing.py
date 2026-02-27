"""INTG005: Missing Package Lockfile.

Detects MCP servers launched via package managers without evidence of a lockfile. Without a
lockfile, dependency resolution is non-deterministic and vulnerable to substitution attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_LOCKFILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
    "Cargo.lock",
    "go.sum",
}
_PKG_MANAGERS = {"npm", "npx", "yarn", "pnpm", "pip", "pipx", "uvx", "poetry", "bundle", "cargo"}


class LockfileMissingCheck(BaseCheck):
    """Missing Package Lockfile."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type != "stdio" or not snapshot.command:
            return findings

        cmd_base = snapshot.command.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if cmd_base not in _PKG_MANAGERS:
            return findings

        all_text = " ".join([snapshot.command] + list(snapshot.args))
        config_text = str(snapshot.config_raw) if snapshot.config_raw else ""
        combined = all_text + " " + config_text

        found = any(lf in combined for lf in _LOCKFILE_NAMES)
        if not found:
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
                    status_extended=f"Package manager '{cmd_base}' used without lockfilereference.",
                    evidence=f"command={cmd_base}, no lockfile in args/config",
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
                    status_extended="Lockfile reference found in configuration.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
