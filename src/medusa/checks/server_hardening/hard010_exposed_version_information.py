"""HARD010: Exposed Version Information.

Detects MCP servers that expose version information in response headers, error messages,
capability declarations, or server metadata. Version information helps attackers identify
specific software releases and their known vulnerabilities.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_VERSION_PATTERN = re.compile(r"\d+\.\d+(?:\.\d+)?")


class ExposedVersionInformationCheck(BaseCheck):
    """Exposed Version Information."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        # Check server_info for version exposure
        version = ""
        if snapshot.server_info:
            version = str(snapshot.server_info.get("version", ""))

        if version and _VERSION_PATTERN.search(version):
            return [
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
                        f"Server '{snapshot.server_name}' exposes version '{version}' in "
                        f"server_info. Version disclosure aids targeted exploitation."
                    ),
                    evidence=f"server_info.version={version!r}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        return [
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
                    f"Server '{snapshot.server_name}' does not expose version information."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
