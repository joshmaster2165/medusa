"""PRIV-017: System Service Management.

Detects tools that can start, stop, restart, enable, or disable system
services (systemctl, service, sc.exe, initd), enabling persistent backdoors.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SERVICE_MGMT_PATTERN = re.compile(
    r"\b(systemctl\s+(start|stop|restart|enable|disable|reload)|"
    r"service\s+\w+\s+(start|stop|restart)|"
    r"sc\.exe\s+(start|stop|create|delete)|"
    r"service_start|service_stop|service_restart|"
    r"start_service|stop_service|restart_service|"
    r"manage_service|daemon_reload)\b",
    re.IGNORECASE,
)


class ServiceManagementCheck(BaseCheck):
    """Detect tools with system service management capability."""

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
            searchable = f"{tool_name} {description} {schema_str}"

            match = _SERVICE_MGMT_PATTERN.search(searchable)
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
                        f"Tool '{tool_name}' can manage system services "
                        f"('{match.group(0)}'), enabling service disruption and backdoors."
                    ),
                    evidence=f"Service management keyword: {match.group(0)}",
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
                    status_extended="No service management tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
