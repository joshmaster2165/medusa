"""RES-016: Missing URI Normalization.

Checks resource URIs for normalization issues — URL-encoded characters
in paths that may bypass access controls (%2f, %2e, uppercase variants).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

ENCODING_ANOMALY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"%2[fF]", re.IGNORECASE),  # Encoded /
    re.compile(r"%2[eE]", re.IGNORECASE),  # Encoded .
    re.compile(r"%5[cC]", re.IGNORECASE),  # Encoded backslash
    re.compile(r"//+"),  # Double slashes
    re.compile(r"\./"),  # Dot-slash
    re.compile(r"/\.$"),  # Trailing dot
]


class ResourceUriNormalizationCheck(BaseCheck):
    """Missing URI Normalization."""

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

            matched = [p.pattern for p in ENCODING_ANOMALY_PATTERNS if p.search(uri)]
            if matched:
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
                            f"Resource '{res_name}' URI '{uri[:80]}' has normalization "
                            f"anomalies that may bypass access controls: {matched[0]}"
                        ),
                        evidence=f"uri={uri!r}, patterns={matched[:3]}",
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
                    status_extended="No URI normalization anomalies detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
