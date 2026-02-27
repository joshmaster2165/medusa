"""INTG012: Dependency Confusion Risk.

Detects MCP server configurations that mix public and private package registry references,
creating dependency confusion attack vectors. Attackers can register packages on public registries
to shadow private package names.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_PUBLIC_REGISTRIES = {"registry.npmjs.org", "pypi.org", "rubygems.org", "crates.io"}
_PRIVATE_REGISTRY_PATTERN = re.compile(
    r"--registry[=\s]+https?://(?!registry\.npmjs\.org|pypi\.org)(\S+)", re.IGNORECASE
)


class DependencyConfusionRiskCheck(BaseCheck):
    """Dependency Confusion Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type != "stdio" or not snapshot.command:
            return findings

        args_str = " ".join(snapshot.args)
        private_matches = _PRIVATE_REGISTRY_PATTERN.findall(args_str)

        if private_matches:
            has_public_too = any(pub in args_str for pub in _PUBLIC_REGISTRIES)
            if has_public_too:
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
                        status_extended="Mixed public and private registry references detected —"
                        "dependency confusion risk.",
                        evidence=f"private={private_matches[0]}",
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
                    status_extended="No dependency confusion risk detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
