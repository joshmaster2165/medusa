"""SSRF-018: Internal API Exposure.

Detects tool descriptions referencing internal API path prefixes (/internal/,
/admin/, /actuator/, /metrics/, etc.) that indicate exposure of internal-only endpoints.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_INTERNAL_API_PATTERN = re.compile(
    r"/(internal|admin|actuator|metrics|health|debug|management|backstage|private|ops)/",
    re.IGNORECASE,
)


class InternalApiExposureCheck(BaseCheck):
    """Detect tools referencing internal API path prefixes."""

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
            searchable = f"{tool.get('description', '')} {str(tool.get('inputSchema', {}))}"
            match = _INTERNAL_API_PATTERN.search(searchable)
            if not match:
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
                        f"Tool '{tool_name}' references internal API path "
                        f"'{match.group(0)}', exposing internal-only endpoints."
                    ),
                    evidence=f"Internal API path reference: {match.group(0)}",
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
                    status_extended="No internal API path references detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
