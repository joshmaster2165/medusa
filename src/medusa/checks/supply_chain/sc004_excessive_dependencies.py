"""SC004: Excessive Dependency Count.

Detects MCP servers with an excessive number of transitive dependencies. Each additional
dependency increases the attack surface and the likelihood of including a compromised package.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAX_DEPS = 20
_INSTALL_CMDS = {"install", "add", "i"}


class ExcessiveDependenciesCheck(BaseCheck):
    """Excessive Dependency Count."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type != "stdio" or not snapshot.command:
            return findings

        args = list(snapshot.args)
        has_install = any(a.lower() in _INSTALL_CMDS for a in args)
        if not has_install:
            return findings

        pkg_count = sum(1 for a in args if not a.startswith("-") and a.lower() not in _INSTALL_CMDS)

        if pkg_count > _MAX_DEPS:
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
                    status_extended=f"Excessive dependency count: {pkg_count} packages"
                    f"(threshold: {_MAX_DEPS}).",
                    evidence=f"package_count={pkg_count}, threshold={_MAX_DEPS}",
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
                    status_extended=f"Dependency count ({pkg_count}) is within threshold.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
