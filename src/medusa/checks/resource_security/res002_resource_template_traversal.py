r"""RES-002: Resource Template Path Traversal.

Checks resource URIs for path traversal patterns (../, ..\, %2e%2e).
Flags resources with template variables that could enable traversal.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"\.\.\\", re.IGNORECASE),
    re.compile(r"%2e%2e[%2f%5c]", re.IGNORECASE),
    re.compile(r"\.\.", re.IGNORECASE),
]
TEMPLATE_VAR_PATTERN = re.compile(r"\{[^}]*(?:path|file|dir|folder|name)[^}]*\}", re.IGNORECASE)


class ResourceTemplateTraversalCheck(BaseCheck):
    """Resource Template Path Traversal."""

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
            if not uri:
                continue

            traversal_found = any(p.search(uri) for p in TRAVERSAL_PATTERNS)
            template_path_var = bool(TEMPLATE_VAR_PATTERN.search(uri))

            if traversal_found or template_path_var:
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
                            f"Resource '{res_name}' URI '{uri}' contains path traversal "
                            f"patterns or unvalidated path template variables."
                        ),
                        evidence=f"uri={uri!r}",
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
                    status_extended=(
                        f"No path traversal patterns detected in "
                        f"{len(snapshot.resources)} resource URI(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
