"""AUTH018: Missing Mutual TLS.

Detects MCP servers that do not require client certificate authentication (mutual TLS). Without
mTLS, the server cannot cryptographically verify the identity of connecting clients, relying
solely on application-layer credentials that may be stolen or forged.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_MTLS_KEYS = {
    "mtls",
    "mutual_tls",
    "client_cert",
    "client_certificate",
    "client_ca",
    "client_auth",
    "require_client_cert",
    "ca_cert",
    "ca_bundle",
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


class MissingMutualTlsCheck(BaseCheck):
    """Missing Mutual TLS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_mtls = _walk_config(snapshot.config_raw or {}, _MTLS_KEYS)
        if not has_mtls:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="mtls",
                    status_extended=(
                        f"Server '{snapshot.server_name}' does not require mutual TLS (mTLS). "
                        f"Client identity cannot be cryptographically verified."
                    ),
                    evidence="No mtls/client_cert configuration keys found",
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
                resource_name="mtls",
                status_extended=(f"Server '{snapshot.server_name}' has mutual TLS configured."),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
