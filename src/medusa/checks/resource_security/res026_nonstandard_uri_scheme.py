"""RES026: Nonstandard Resource URI Scheme.

Detects resources that use nonstandard URI schemes which could enable SSRF,
confuse client URI parsers, or mask malicious endpoints behind unfamiliar
protocol handlers.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.resource_patterns import STANDARD_URI_SCHEMES


class NonstandardUriSchemeCheck(BaseCheck):
    """Nonstandard Resource URI Scheme."""

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
            resource_name = resource.get("name", uri)

            # Extract scheme
            if "://" not in uri:
                continue  # No scheme to validate

            scheme = uri.split("://")[0].lower()

            if scheme and scheme not in STANDARD_URI_SCHEMES:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=resource_name,
                        status_extended=(
                            f"Resource '{resource_name}' uses nonstandard URI "
                            f"scheme '{scheme}://'. Nonstandard schemes could "
                            f"enable SSRF, confuse client URI parsers, or mask "
                            f"malicious endpoints."
                        ),
                        evidence=f"uri={uri}, scheme={scheme}",
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
                        f"All {len(snapshot.resources)} resource(s) use standard URI schemes."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
