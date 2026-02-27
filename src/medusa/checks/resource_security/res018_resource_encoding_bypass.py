"""RES018: Resource Encoding Bypass.

Detects MCP resource handlers that fail to properly handle character encoding variations,
allowing attackers to bypass content filters and access controls using alternative encodings
such as UTF-7, UTF-16, double URL encoding, or mixed encoding schemes.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Encoding bypass patterns that suggest double/alternate encoding
ENCODING_BYPASS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"%25[2-9a-fA-F][0-9a-fA-F]"),  # Double URL encoding (%25 = %)
    re.compile(r"%u[0-9a-fA-F]{4}"),  # Unicode escape (%uXXXX)
    re.compile(r"\+\+"),  # Double plus encoding
    re.compile(r"%c0%a[ef]", re.IGNORECASE),  # UTF-8 overlong encoding for /
    re.compile(r"%c1%9c", re.IGNORECASE),  # UTF-8 overlong backslash
    re.compile(r"\\u[0-9a-fA-F]{4}"),  # JSON unicode escape in URI
    re.compile(r"%0[0-9a-fA-F]"),  # Null byte and control chars
]

ENCODING_NORMALIZATION_KEYS: set[str] = {
    "normalize_encoding",
    "encoding_check",
    "unicode_normalization",
    "decode_validation",
    "encoding_validation",
    "charset_validation",
}


class ResourceEncodingBypassCheck(BaseCheck):
    """Resource Encoding Bypass."""

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

            matched = [p.pattern for p in ENCODING_BYPASS_PATTERNS if p.search(uri)]
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
                            f"Resource '{res_name}' URI contains encoding bypass patterns "
                            f"that may evade access controls."
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
                    status_extended="No encoding bypass patterns detected in resource URIs.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
