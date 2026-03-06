"""AUDIT011: Server Missing Logging Capability.

Checks whether the MCP server advertises the logging capability in its
initialization response. Without server-side logging, there is no audit trail
for tool invocations, making incident detection and forensic analysis impossible.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class MissingLoggingCapabilityCheck(BaseCheck):
    """Detect servers missing the MCP logging capability."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        capabilities = snapshot.capabilities
        has_logging = capabilities.get("logging") is not None

        if not has_logging:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        "Server does not advertise the MCP logging "
                        "capability. Without server-side logging, there "
                        "is no audit trail for tool invocations, making "
                        "incident detection and forensic analysis "
                        "impossible."
                    ),
                    evidence=f"capabilities={list(capabilities.keys())}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                    status_extended=("Server advertises logging capability."),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
