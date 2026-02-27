"""SSRF-011: Missing Egress Allowlist.

Checks server configuration for an explicit egress allowlist. Absence means
tools can contact arbitrary external services without restriction.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_ALLOWLIST_KEYS = {
    "allowlist",
    "allow_list",
    "whitelist",
    "permitted_domains",
    "allowed_domains",
    "egress_allowlist",
    "egress_filter",
    "domain_allowlist",
    "network_allowlist",
    "outbound_allowlist",
}


class MissingEgressAllowlistCheck(BaseCheck):
    """Check for absence of egress allowlist configuration."""

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
        args_str = " ".join(snapshot.args).lower()
        combined = f"{config_str} {args_str}"

        has_allowlist = any(k in combined for k in _ALLOWLIST_KEYS)

        if not has_allowlist:
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
                        "No egress allowlist configuration detected. Tools can "
                        "contact arbitrary external destinations, enabling data "
                        "exfiltration and unauthorized API calls."
                    ),
                    evidence="No allowlist/whitelist/permitted_domains keys found in serverconfig.",
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
                    status_extended="Egress allowlist configuration detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
