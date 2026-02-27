"""SSRF-004: Unrestricted Network Egress.

Tools that accept URL parameters without a domain allowlist can be used to
make outbound requests to any destination. Flags tools with URL-type params
that lack pattern/enum constraints (domain allowlist proxy).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.ssrf import URL_PARAM_NAMES

_ALLOWLIST_KEYS = {
    "allowlist",
    "allow_list",
    "allowed_domains",
    "domain_whitelist",
    "egress_filter",
    "egress_allowlist",
    "permitted_domains",
}


class UnrestrictedEgressCheck(BaseCheck):
    """Detect tools that allow unrestricted egress without domain allowlists."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        config_str = str(snapshot.config_raw).lower() if snapshot.config_raw else ""
        has_config_allowlist = any(k in config_str for k in _ALLOWLIST_KEYS)

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )

            url_params = [p for p in properties if p.lower() in URL_PARAM_NAMES]
            if not url_params:
                continue

            if has_config_allowlist:
                continue

            # Check for schema-level domain constraints
            has_schema_restriction = any(
                bool(properties[p].get("pattern") or properties[p].get("enum"))
                for p in url_params
                if isinstance(properties[p], dict)
            )
            if has_schema_restriction:
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
                        f"Tool '{tool_name}' accepts URL parameter(s) {url_params} "
                        f"without a domain allowlist, enabling unrestricted egress."
                    ),
                    evidence=f"Unrestricted URL params: {url_params}; no egress allowlist in"
                    f"config.",
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
                    status_extended="No unrestricted egress tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
