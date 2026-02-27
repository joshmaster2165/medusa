"""SSRF-014: File Scheme URL Access.

Detects tools whose descriptions, resource URIs, or default parameter values
reference file:// URLs, indicating direct local filesystem access capability.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_FILE_SCHEME_PATTERN = re.compile(r"\bfile://", re.IGNORECASE)


class FileSchemeAccessCheck(BaseCheck):
    """Detect file:// scheme references in tool definitions and resources."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Check tools
        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            searchable = f"{tool.get('description', '')} {str(tool.get('inputSchema', {}))}"
            if _FILE_SCHEME_PATTERN.search(searchable):
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' references file:// scheme, "
                            f"enabling local filesystem access via URL."
                        ),
                        evidence="file:// reference found in tool definition.",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Check resources
        for resource in snapshot.resources:
            uri = resource.get("uri", "")
            if _FILE_SCHEME_PATTERN.search(uri):
                res_name = resource.get("name", uri)
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=res_name,
                        status_extended=(f"Resource '{res_name}' uses file:// URI: {uri}"),
                        evidence=f"file:// URI: {uri}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and (snapshot.tools or snapshot.resources):
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
                    status_extended="No file:// scheme references detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
