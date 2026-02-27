"""SSRF-015: Gopher/Dict Protocol Risk.

Detects references to gopher:// or dict:// schemes in tool descriptions or
schemas. These protocols enable raw TCP communication with internal services.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_DANGEROUS_PROTO_PATTERN = re.compile(r"\b(gopher|dict|tftp|ldap)://", re.IGNORECASE)


class GopherProtocolRiskCheck(BaseCheck):
    """Detect gopher:// and dict:// protocol references in tool definitions."""

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
            match = _DANGEROUS_PROTO_PATTERN.search(searchable)
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
                        f"Tool '{tool_name}' references dangerous protocol "
                        f"'{match.group(0)}', enabling raw TCP access to internal services."
                    ),
                    evidence=f"Dangerous protocol reference: {match.group(0)}",
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
                    status_extended="No gopher/dict protocol references detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
