"""SSRF-005: Localhost Access Risk.

Tools with URL-type parameters that reference localhost or have no blocking
of loopback addresses allow access to services on the server host itself.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import LOCALHOST_PATTERNS, URL_PARAM_NAMES


class LocalhostAccessCheck(BaseCheck):
    """Detect tools that could access localhost services without restriction."""

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
            description = tool.get("description", "") or ""

            url_params = [p for p in properties if p.lower() in URL_PARAM_NAMES]
            if not url_params:
                continue

            # Check if description or schema references localhost
            searchable = f"{description} {str(input_schema)}"
            localhost_hit = any(pat.search(searchable) for pat in LOCALHOST_PATTERNS)

            # Or: URL params exist with no pattern blocking localhost
            has_pattern = all(
                bool(properties[p].get("pattern") or properties[p].get("enum"))
                for p in url_params
                if isinstance(properties[p], dict)
            )

            if localhost_hit or not has_pattern:
                reason = (
                    "references localhost"
                    if localhost_hit
                    else "no localhost-blocking constraint on URL params"
                )
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
                            f"Tool '{tool_name}' could enable localhost access ({reason}), "
                            f"allowing exploitation of co-located services."
                        ),
                        evidence=f"URL params: {url_params}; {reason}",
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
                    status_extended="No localhost access risk detected in tool definitions.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
