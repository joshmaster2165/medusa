"""SHADOW009: Outdated Protocol Version.

Detects MCP servers that report a missing, unrecognized, or outdated protocol version.
Older protocol versions may lack security features present in the current specification.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.identity import (
    CURRENT_MCP_PROTOCOL_VERSION,
    KNOWN_MCP_PROTOCOL_VERSIONS,
)


class OutdatedProtocolCheck(BaseCheck):
    """Outdated Protocol Version."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        protocol_version = snapshot.protocol_version

        if not protocol_version:
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
                        "Server does not report a protocol version. Without "
                        "protocol version information, clients cannot determine "
                        "supported security features or compatibility."
                    ),
                    evidence="protocol_version=<empty>",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        elif protocol_version not in KNOWN_MCP_PROTOCOL_VERSIONS:
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
                        f"Server reports unrecognized protocol version "
                        f"'{protocol_version}'. This may indicate a custom or "
                        f"modified MCP implementation."
                    ),
                    evidence=(
                        f"protocol_version={protocol_version}, known={KNOWN_MCP_PROTOCOL_VERSIONS}"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        elif protocol_version != CURRENT_MCP_PROTOCOL_VERSION:
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
                        f"Server uses outdated protocol version "
                        f"'{protocol_version}' (current: "
                        f"{CURRENT_MCP_PROTOCOL_VERSION}). Older protocol "
                        f"versions may lack security features."
                    ),
                    evidence=(
                        f"protocol_version={protocol_version}, "
                        f"current={CURRENT_MCP_PROTOCOL_VERSION}"
                    ),
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
                    status_extended=(f"Server uses current protocol version: {protocol_version}"),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
