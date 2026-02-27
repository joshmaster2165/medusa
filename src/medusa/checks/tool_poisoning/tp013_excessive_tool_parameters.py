"""TP013: Excessive Tool Parameter Count.

Detects tools with an unreasonably large number of parameters, which may indicate complexity
designed to hide malicious parameters among legitimate ones. An excessive parameter count
increases the attack surface and makes manual review impractical.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAX_PARAMS: int = 15


class ExcessiveToolParametersCheck(BaseCheck):
    """Excessive Tool Parameter Count."""

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
            tool_name: str = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_count = len(properties)

            if param_count > _MAX_PARAMS:
                param_names = list(properties.keys())[:10]
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
                            f"Tool '{tool_name}' has {param_count} parameters "
                            f"(threshold is {_MAX_PARAMS}). Excessive parameters "
                            f"obscure review and may hide exfiltration vectors."
                        ),
                        evidence=(
                            f"{param_count} parameters (threshold {_MAX_PARAMS}). "
                            f"First 10: {', '.join(param_names)}"
                        ),
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
                    status_extended=(
                        f"All {len(snapshot.tools)} tool(s) have {_MAX_PARAMS} or fewer parameters."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
