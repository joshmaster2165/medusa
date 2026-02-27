"""PRIV-015: Firewall Rule Modification.

Detects tools referencing iptables, nftables, Windows Firewall, or cloud
security group rule modification, enabling network control bypass.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_FIREWALL_PATTERN = re.compile(
    r"\b(iptables|ip6tables|nftables|ufw|firewalld|netfilter|"
    r"windows.firewall|netsh.*firewall|security.group|"
    r"modify.*firewall|firewall.*rule|add.*rule.*firewall|"
    r"update.*security.*group|revoke.*ingress|authorize.*ingress)\b",
    re.IGNORECASE,
)


class FirewallModificationCheck(BaseCheck):
    """Detect tools with firewall rule modification capability."""

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

            match = _FIREWALL_PATTERN.search(searchable)
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
                        f"Tool '{tool_name}' can modify firewall rules "
                        f"('{match.group(0)}'), exposing internal services."
                    ),
                    evidence=f"Firewall modification keyword: {match.group(0)}",
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
                    status_extended="No firewall modification tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
