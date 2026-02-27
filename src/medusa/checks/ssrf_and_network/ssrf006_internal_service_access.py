"""SSRF-006: Internal Service Access.

Detects tool descriptions or schemas referencing internal service hostnames
(.internal, .local, .svc.cluster.local) that indicate access to internal infrastructure.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import INTERNAL_SERVICE_PATTERNS


class InternalServiceAccessCheck(BaseCheck):
    """Detect tools referencing internal service hostname patterns."""

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
            description = tool.get("description", "") or ""
            schema_str = str(tool.get("inputSchema") or {})
            searchable = f"{description} {schema_str}"

            matched_patterns: list[str] = []
            for pat in INTERNAL_SERVICE_PATTERNS:
                m = pat.search(searchable)
                if m:
                    matched_patterns.append(m.group(0))

            if not matched_patterns:
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
                        f"Tool '{tool_name}' references internal service hostname(s): "
                        f"{matched_patterns}, indicating access to internal infrastructure."
                    ),
                    evidence=f"Internal hostnames found: {matched_patterns}",
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
                    status_extended="No internal service hostname references detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
