"""SSRF-013: Port Scanning Risk.

Detects tools with unconstrained port parameters that allow arbitrary port
specification, enabling port scanning of internal or external hosts.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_PORT_PARAM_NAMES = {"port", "ports", "port_number", "port_range", "dst_port", "src_port"}


class PortScanningRiskCheck(BaseCheck):
    """Detect tools with unconstrained port parameters enabling port scanning."""

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
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )

            port_params = [p for p in properties if p.lower() in _PORT_PARAM_NAMES]
            if not port_params:
                continue

            # Check if port is constrained to specific values
            unconstrained = [
                p
                for p in port_params
                if isinstance(properties.get(p), dict)
                and not properties[p].get("enum")
                and not properties[p].get("const")
                and not (
                    properties[p].get("minimum") is not None
                    and properties[p].get("maximum") is not None
                    and properties[p]["maximum"] - properties[p]["minimum"] < 10
                )
            ]

            if not unconstrained:
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
                        f"Tool '{tool_name}' has unconstrained port parameter(s) "
                        f"{unconstrained}, enabling arbitrary port scanning."
                    ),
                    evidence=f"Unconstrained port params: {unconstrained}",
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
                    status_extended="No port scanning risk detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
