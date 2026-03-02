"""HARD017: Permissive Server Capabilities.

Detects servers that declare all major MCP capabilities (tools,
resources, prompts, sampling, logging) without restrictions. Enabling
everything suggests no principle of least privilege is applied.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAJOR_CAPABILITIES: list[str] = [
    "tools",
    "resources",
    "prompts",
    "sampling",
    "logging",
]


class PermissiveCapabilitiesCheck(BaseCheck):
    """Permissive Server Capabilities."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.capabilities:
            return findings

        enabled: list[str] = []
        for cap in _MAJOR_CAPABILITIES:
            value = snapshot.capabilities.get(cap)
            if value:
                enabled.append(cap)

        all_enabled = len(enabled) == len(_MAJOR_CAPABILITIES)

        if all_enabled:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"declares all {len(enabled)} "
                        f"major capabilities enabled. "
                        f"This violates the principle of "
                        f"least privilege."
                    ),
                    evidence=(f"enabled_capabilities={', '.join(enabled)}"),
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
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"has {len(enabled)} of "
                        f"{len(_MAJOR_CAPABILITIES)} "
                        f"major capabilities enabled."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
