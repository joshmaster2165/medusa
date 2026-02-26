"""SHADOW-002: Unverified Server Identity.

Detects MCP servers that do not provide proper identity information in
their server_info response (missing or empty name/version fields).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class UnverifiedServerIdentityCheck(BaseCheck):
    """Check for missing or incomplete server identity information."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        issues: list[str] = []

        if not snapshot.server_info:
            issues.append("server_info is empty or not provided")
        else:
            name = snapshot.server_info.get("name", "")
            version = snapshot.server_info.get("version", "")

            if not name or not str(name).strip():
                issues.append("server_info is missing a 'name' field")

            if not version or not str(version).strip():
                issues.append("server_info is missing a 'version' field")

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
                    status_extended=(
                        f"Server '{snapshot.server_name}' has incomplete "
                        f"identity information: {'; '.join(issues)}. "
                        f"This makes it vulnerable to impersonation."
                    ),
                    evidence=f"server_info={snapshot.server_info}",
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
                        f"Server '{snapshot.server_name}' provides complete "
                        f"identity information (name and version) in "
                        f"server_info."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
