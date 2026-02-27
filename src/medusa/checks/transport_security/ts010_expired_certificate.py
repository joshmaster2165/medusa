"""TS010: Expired TLS Certificate.

Detects MCP servers with expired TLS certificates. Expired certificates cause connection errors
in properly configured clients and may lead administrators to disable certificate validation to
restore service, removing all TLS authentication guarantees.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_EXPIRY_MONITOR_KEYS = {
    "cert_expiry",
    "cert_expiry_check",
    "certificate_expiry",
    "tls_expiry",
    "cert_monitoring",
    "cert_monitor",
    "cert_renewal",
    "auto_renew",
    "cert_expire_check",
}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class ExpiredCertificateCheck(BaseCheck):
    """Expired TLS Certificate."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_expiry_monitoring = _walk_config(snapshot.config_raw or {}, _EXPIRY_MONITOR_KEYS)
        if not has_expiry_monitoring:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="tls.cert_expiry",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no certificate expiry monitoring. "
                        f"Certificates may expire undetected, causing outages or bypassed"
                        f"validation."
                    ),
                    evidence="No cert_expiry/cert_monitoring/auto_renew configuration found",
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
                resource_name="tls.cert_expiry",
                status_extended=(
                    f"Server '{snapshot.server_name}' has certificate expiry monitoring configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
