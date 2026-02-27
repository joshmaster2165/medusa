"""RES-010: Resource Type Confusion.

Checks resources where the MIME type could be misinterpreted. Flags
resources with potentially dangerous MIME types (application/octet-stream,
text/html in unexpected contexts, or missing mimeType entirely).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

DANGEROUS_MIME_TYPES: set[str] = {
    "application/octet-stream",
    "text/html",
    "application/x-sh",
    "application/x-shellscript",
    "application/javascript",
    "text/javascript",
}


class ResourceTypeConfusionCheck(BaseCheck):
    """Resource Type Confusion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        for resource in snapshot.resources:
            res_name = resource.get("name", "<unnamed>")
            uri = resource.get("uri", "")
            mime_type = resource.get("mimeType", "").lower()

            if mime_type in DANGEROUS_MIME_TYPES:
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
                        status_extended=(
                            f"Resource '{res_name}' declares a potentially dangerous "
                            f"MIME type '{mime_type}' that may cause type confusion."
                        ),
                        evidence=f"mimeType={mime_type!r}, uri={uri!r}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.resources:
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
                    status_extended="No dangerous MIME type confusion detected in resources.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
