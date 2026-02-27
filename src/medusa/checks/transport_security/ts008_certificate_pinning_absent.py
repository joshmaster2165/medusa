"""TS008: Certificate Pinning Absent.

Detects MCP connections without certificate pinning for critical communication channels. Without
pinning, any certificate authority can issue a certificate for the server's domain, enabling
man-in-the-middle attacks by compromised or coerced CAs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_PINNING_KEYS = {
    "certificate_pinning",
    "cert_pinning",
    "pin_sha256",
    "hpkp",
    "public_key_pin",
    "cert_pin",
    "ssl_pin",
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


class CertificatePinningAbsentCheck(BaseCheck):
    """Certificate Pinning Absent."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_pinning = _walk_config(snapshot.config_raw or {}, _PINNING_KEYS)
        if not has_pinning:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="tls.pinning",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no certificate pinning. "
                        f"Any CA can issue a cert for this domain, enabling MITM attacks."
                    ),
                    evidence="No certificate_pinning/pin_sha256/hpkp configuration found",
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
                resource_name="tls.pinning",
                status_extended=(
                    f"Server '{snapshot.server_name}' has certificate pinning configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
