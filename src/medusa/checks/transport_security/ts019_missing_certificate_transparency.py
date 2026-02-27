"""TS019: Missing Certificate Transparency.

Detects absence of Certificate Transparency (CT) log monitoring for MCP server certificates.
Without CT monitoring, unauthorized certificate issuance for the server's domain goes
undetected, enabling unnoticed man-in-the-middle attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_CT_CONFIG_KEYS = {
    "certificate_transparency",
    "ct_monitoring",
    "ct_logs",
    "ct_log",
    "expect_ct",
    "expect-ct",
    "sct",
    "signed_certificate_timestamp",
    "ct_spotter",
    "cert_spotter",
    "ct_monitor",
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


def _has_ct_in_headers(config: dict) -> bool:
    """Check for Expect-CT header in headers config."""
    headers = config.get("headers") or {}
    if not isinstance(headers, dict):
        return False
    return any(k.lower() in {"expect-ct", "expect_ct"} for k in headers)


class MissingCertificateTransparencyCheck(BaseCheck):
    """Missing Certificate Transparency."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        config = snapshot.config_raw or {}
        has_ct = _walk_config(config, _CT_CONFIG_KEYS) or _has_ct_in_headers(config)
        if not has_ct:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="certificate.transparency",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no Certificate Transparency "
                        f"monitoring configured. Unauthorized certificate issuance goes undetected."
                    ),
                    evidence="No CT monitoring (expect_ct/ct_logs/ct_monitor) configuration found",
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
                resource_name="certificate.transparency",
                status_extended=(
                    f"Server '{snapshot.server_name}' has Certificate Transparency monitoring "
                    f"configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
