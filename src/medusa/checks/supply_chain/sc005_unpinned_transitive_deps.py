"""SC005: Unpinned Transitive Dependencies.

Detects MCP server dependency configurations where transitive dependencies are not version-
constrained. Unpinned transitive dependencies can silently update to malicious versions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_UNSAFE_FLAGS = {"--legacy-peer-deps", "--force", "--shamefully-hoist"}
_WILDCARD_VERSIONS = {"*", "latest", "next", "canary"}


class UnpinnedTransitiveDepsCheck(BaseCheck):
    """Unpinned Transitive Dependencies."""

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
        unsafe = [a for a in args if a.lower() in _UNSAFE_FLAGS]
        wildcards = [
            a for a in args if "@" in a and any(a.endswith(f"@{v}") for v in _WILDCARD_VERSIONS)
        ]

        issues: list[str] = []
        if unsafe:
            issues.append(f"unsafe flags: {', '.join(unsafe)}")
        if wildcards:
            issues.append(f"wildcard versions: {', '.join(wildcards)}")

        if issues:
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
                    status_extended=f"Unpinned dependency risks: {'; '.join(issues)}",
                    evidence=f"issues={'; '.join(issues)}",
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
                    status_extended="No unpinned transitive dependency risks detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
