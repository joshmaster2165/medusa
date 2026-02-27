"""SSRF-012: Network Scanning Capability.

Detects tools with both host and port parameters (or scan-related names) that
could be used to perform host discovery or port scanning on internal networks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HOST_PARAMS = {"host", "hostname", "target", "ip", "ip_address", "address", "destination"}
_PORT_PARAMS = {"port", "ports", "port_range", "port_number"}
_SCAN_TOOL_KEYWORDS = {"scan", "probe", "ping", "nmap", "discover", "enumerate"}


class NetworkScanningCapabilityCheck(BaseCheck):
    """Detect tools that could be used for internal network scanning."""

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
            name_lower = tool_name.lower()
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )
            param_names = {p.lower() for p in properties}

            has_host = bool(param_names & _HOST_PARAMS)
            has_port = bool(param_names & _PORT_PARAMS)
            has_scan_name = any(kw in name_lower for kw in _SCAN_TOOL_KEYWORDS)

            if not (has_scan_name or (has_host and has_port)):
                continue

            reason = []
            if has_scan_name:
                reason.append(f"tool name '{tool_name}' suggests scanning")
            if has_host and has_port:
                host_p = list(param_names & _HOST_PARAMS)
                port_p = list(param_names & _PORT_PARAMS)
                reason.append(f"host params {host_p} + port params {port_p}")

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
                        f"Tool '{tool_name}' has network scanning capability: {'; '.join(reason)}."
                    ),
                    evidence="; ".join(reason),
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
                    status_extended="No network scanning capability detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
