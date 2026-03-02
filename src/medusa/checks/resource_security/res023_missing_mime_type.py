"""RES-023: Resource Without MIME Type.

Detects resources that do not specify a MIME type. Missing MIME types
enable MIME confusion attacks where the client may interpret content
differently than intended by the server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class MissingMimeTypeCheck(BaseCheck):
    """Resource Without MIME Type."""

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
            uri = resource.get("uri", "")
            name = resource.get("name", "<unnamed>")
            mime_type = resource.get("mimeType")

            if not mime_type or not str(mime_type).strip():
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=name,
                        status_extended=(
                            f"Resource '{name}' does not specify a MIME type. "
                            f"Clients may misinterpret the content format. "
                            f"URI: {uri}"
                        ),
                        evidence="mimeType field is missing or empty.",
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
                    status_extended=(
                        f"All {len(snapshot.resources)} resource(s) specify "
                        f"a MIME type."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
