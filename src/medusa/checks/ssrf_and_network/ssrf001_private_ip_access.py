"""SSRF-001: Private IP Address Access.

Detects tools with URL-type parameters that lack IP range restrictions,
allowing requests to RFC-1918 private addresses (10.x, 172.16.x, 192.168.x).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import URL_PARAM_NAMES


class PrivateIpAccessCheck(BaseCheck):
    """Detect tools that accept unrestricted URL/host params (private IP risk)."""

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

            url_params = [p for p in properties if p.lower() in URL_PARAM_NAMES]
            if not url_params:
                continue

            # Check if any URL param has a pattern/enum constraint
            restricted = all(
                bool(properties[p].get("pattern") or properties[p].get("enum"))
                for p in url_params
                if isinstance(properties[p], dict)
            )
            if restricted:
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
                        f"Tool '{tool_name}' accepts URL parameter(s) "
                        f"{url_params} without IP range restrictions, enabling "
                        f"SSRF against private IP ranges."
                    ),
                    evidence=f"URL params without constraints: {url_params}",
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
                    status_extended="No unrestricted URL parameters found that could enable"
                    "private IP access.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
