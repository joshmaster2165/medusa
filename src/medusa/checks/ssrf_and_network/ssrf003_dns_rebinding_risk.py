"""SSRF-003: DNS Rebinding Risk.

Checks server configuration for DNS resolution/caching settings that protect
against DNS rebinding. Absence of post-resolution validation hints means the
server may be vulnerable to DNS rebinding attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_DNS_PROTECTION_KEYS = {
    "dns_cache",
    "dns_rebinding",
    "dns_validation",
    "resolve_ip",
    "pin_ip",
    "ip_validation",
    "post_resolve",
    "dns_cache_ttl",
    "dns_rebind_protection",
    "dns_pinning",
}


class DnsRebindingRiskCheck(BaseCheck):
    """Check for absence of DNS rebinding protection in server config."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Check config for DNS protection hints
        config_str = str(snapshot.config_raw).lower() if snapshot.config_raw else ""
        args_str = " ".join(snapshot.args).lower()
        combined = f"{config_str} {args_str}"

        has_protection = any(key in combined for key in _DNS_PROTECTION_KEYS)

        if not has_protection:
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
                        "No DNS rebinding protection configuration detected. "
                        "The server may not validate IP addresses after DNS "
                        "resolution, leaving it vulnerable to DNS rebinding."
                    ),
                    evidence="No DNS caching or post-resolution IP validation keys found inconfig.",
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
                    status_extended="DNS rebinding protection configuration detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
