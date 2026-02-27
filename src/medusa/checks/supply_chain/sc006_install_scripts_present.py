"""SC006: Install Scripts Present.

Detects MCP server dependencies that include install scripts (preinstall, postinstall, or
equivalent lifecycle hooks). Install scripts execute arbitrary code during package installation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_NPM_COMMANDS = {"npm", "npx", "yarn", "pnpm"}


class InstallScriptsPresentCheck(BaseCheck):
    """Install Scripts Present."""

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
        if cmd_base not in _NPM_COMMANDS:
            return findings

        args_lower = [a.lower() for a in snapshot.args]
        has_ignore_scripts = "--ignore-scripts" in args_lower

        if not has_ignore_scripts:
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
                    status_extended=f"Package manager '{cmd_base}' used without"
                    f"--ignore-scripts flag.",
                    evidence=f"command={cmd_base}, missing_flag=--ignore-scripts",
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
                    status_extended="Install scripts are disabled via --ignore-scripts.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
