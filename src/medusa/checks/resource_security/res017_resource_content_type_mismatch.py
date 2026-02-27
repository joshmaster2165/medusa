"""RES017: Resource Content-Type Mismatch.

Detects MCP resources that declare one content type in their metadata but serve content of a
different type. This mismatch can lead to client-side processing errors, security bypass through
type confusion, or exploitation of type-specific parsing vulnerabilities.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Suspicious MIME type pairings: the URI scheme implies a type
# inconsistent with the declared mimeType.
_SCHEME_EXPECTED: dict[str, set[str]] = {
    "file": {
        "text/plain",
        "application/octet-stream",
        "application/json",
        "text/html",
        "text/csv",
        "application/pdf",
        "image/png",
        "image/jpeg",
    },
    "http": {"application/json", "text/html", "text/plain", "application/xml"},
    "https": {"application/json", "text/html", "text/plain", "application/xml"},
}

# mimeTypes that are suspicious for certain URI schemes
_MISMATCH_HINTS: list[tuple[str, str, str]] = [
    # (uri_contains, suspicious_mime_prefix, reason)
    (".json", "text/html", "JSON file declared as HTML"),
    (".html", "application/json", "HTML file declared as JSON"),
    (".xml", "application/json", "XML file declared as JSON"),
    (".csv", "application/json", "CSV file declared as JSON"),
    (".jpg", "text/plain", "JPEG image declared as plain text"),
    (".png", "text/plain", "PNG image declared as plain text"),
    (".pdf", "text/plain", "PDF declared as plain text"),
]


class ResourceContentTypeMismatchCheck(BaseCheck):
    """Resource Content-Type Mismatch."""

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
            uri = resource.get("uri", "").lower()
            mime = resource.get("mimeType", "").lower()

            if not mime or not uri:
                continue

            for uri_suffix, bad_mime_prefix, reason in _MISMATCH_HINTS:
                if uri_suffix in uri and mime.startswith(bad_mime_prefix):
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
                                f"Resource '{res_name}' has a content-type mismatch: {reason}."
                            ),
                            evidence=f"uri={uri!r}, mimeType={mime!r}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )
                    break

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
                    status_extended="No content-type mismatches detected in resources.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
