"""PRIV-004: Cloud Metadata Service Access.

Detects tools that reference cloud metadata service addresses (169.254.169.254,
metadata.google.internal, etc.) in their descriptions or schemas.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import CLOUD_METADATA_URLS


class CloudMetadataAccessCheck(BaseCheck):
    """Detect tools referencing cloud instance metadata endpoints."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            searchable = (
                f"{tool.get('description', '')} {str(tool.get('inputSchema', {}))}"
            ).lower()

            hits = [url for url in CLOUD_METADATA_URLS if url.lower() in searchable]
            if not hits:
                continue

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
                        f"Tool '{tool_name}' references cloud metadata endpoint(s) "
                        f"{hits}, enabling credential theft via instance metadata access."
                    ),
                    evidence=f"Cloud metadata URLs found: {hits}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if not findings and snapshot.tools:
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
                    status_extended="No cloud metadata service references detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
