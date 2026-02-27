"""TS017: DNS Over HTTP.

Detects MCP server DNS resolution performed over unencrypted HTTP instead of DNS-over-HTTPS
(DoH) or DNS-over-TLS (DoT). Unencrypted DNS queries expose the server's communication targets
to network observers and are vulnerable to DNS spoofing.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_DNS_KEYS = {"dns", "dns_server", "resolver", "dns_resolver", "nameserver"}
_SECURE_DNS_KEYS = {
    "dns_over_https",
    "doh",
    "dns_over_tls",
    "dot",
    "secure_dns",
    "encrypted_dns",
    "doh_url",
    "dot_port",
}
_INSECURE_DNS_VALUES = {"8.8.8.8", "1.1.1.1", "9.9.9.9"}  # Plain DNS servers


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class DnsOverHttpCheck(BaseCheck):
    """DNS Over HTTP."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_dns_config = _walk_config(snapshot.config_raw or {}, _DNS_KEYS)
        if not has_dns_config:
            return []
        has_secure_dns = _walk_config(snapshot.config_raw or {}, _SECURE_DNS_KEYS)
        if not has_secure_dns:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="dns.security",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has DNS configuration without DoH/DoT. "
                        f"DNS queries are unencrypted and vulnerable to spoofing."
                    ),
                    evidence="DNS config found but no DNS-over-HTTPS/DoT configuration",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="config",
                resource_name="dns.security",
                status_extended=(f"Server '{snapshot.server_name}' uses encrypted DNS (DoH/DoT)."),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
