"""DP-003: Detect resources missing data classification metadata.

Checks each resource for a declared ``mimeType`` or the presence of data
classification keywords in its description (e.g. "confidential", "public",
"internal", "sensitive", "pii", "restricted", "secret").
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

CLASSIFICATION_KEYWORDS: set[str] = {
    "confidential",
    "public",
    "internal",
    "sensitive",
    "pii",
    "restricted",
    "secret",
}


class MissingDataClassificationCheck(BaseCheck):
    """Check for missing data classification on resources."""

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
            res_name: str = resource.get("name", "<unnamed>")
            mime_type: str | None = resource.get("mimeType")
            description: str = resource.get("description", "")

            has_mime = bool(mime_type)
            has_classification = any(
                kw in description.lower() for kw in CLASSIFICATION_KEYWORDS
            )

            if not has_mime and not has_classification:
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
                            f"Resource '{res_name}' has no mimeType and no data "
                            f"classification keywords in its description."
                        ),
                        evidence=(
                            f"mimeType: {mime_type!r}, "
                            f"description: {description[:100]!r}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Emit PASS if resources were checked but none had issues
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
                    status_extended=(
                        f"All {len(snapshot.resources)} resource(s) have data "
                        f"classification metadata."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
