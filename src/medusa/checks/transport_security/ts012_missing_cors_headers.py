"""TS012: Missing CORS Headers.

Detects HTTP endpoints without Cross-Origin Resource Sharing (CORS) configuration. Missing CORS
headers can either block legitimate cross-origin requests or indicate that no cross-origin
access policy has been considered, potentially defaulting to an insecure state.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.transport import CORS_CONFIG_KEYS

_HTTP_TRANSPORTS = {"http", "sse"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class MissingCorsHeadersCheck(BaseCheck):
    """Missing CORS Headers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_cors = _walk_config(snapshot.config_raw or {}, CORS_CONFIG_KEYS)
        if not has_cors:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="cors",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no CORS configuration. "
                        f"Cross-origin access policy is undefined."
                    ),
                    evidence="No cors/access_control_allow_origin/allowed_origins config found",
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
                resource_name="cors",
                status_extended=(f"Server '{snapshot.server_name}' has CORS headers configured."),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
