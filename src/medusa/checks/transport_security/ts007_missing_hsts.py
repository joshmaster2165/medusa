"""TS007: Missing HSTS Header.

Detects HTTP endpoints served without the Strict-Transport-Security (HSTS) header. Without HSTS,
browsers and clients may connect over HTTP before being redirected to HTTPS, creating a window
for man-in-the-middle attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.transport import HSTS_CONFIG_KEYS

_HTTP_TRANSPORTS = {"http", "sse"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        # Normalise key: lower-case and replace hyphens with underscores so that
        # HTTP header names like "Strict-Transport-Security" match the config key
        # "strict_transport_security".
        normalised = k.lower().replace("-", "_")
        if normalised in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class MissingHstsCheck(BaseCheck):
    """Missing HSTS Header."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_hsts = _walk_config(snapshot.config_raw or {}, HSTS_CONFIG_KEYS)
        if not has_hsts:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="hsts",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no HSTS (Strict-Transport-Security) "
                        f"configuration. Clients may connect over HTTP before upgrading."
                    ),
                    evidence="No hsts/strict_transport_security configuration found",
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
                resource_name="hsts",
                status_extended=(f"Server '{snapshot.server_name}' has HSTS configured."),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
