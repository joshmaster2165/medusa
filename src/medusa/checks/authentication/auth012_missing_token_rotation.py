"""AUTH012: Missing Token Rotation.

Detects long-lived authentication tokens without a rotation mechanism. Tokens that persist for
extended periods without rotation increase the window of opportunity for attackers who have
obtained a compromised token.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_TOKEN_KEYS = {"jwt", "token", "access_token", "auth", "api_key", "apikey"}
_ROTATION_KEYS = {
    "rotation",
    "rotate",
    "refresh",
    "refresh_token",
    "token_rotation",
    "auto_refresh",
    "renew",
    "renewal",
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


class MissingTokenRotationCheck(BaseCheck):
    """Missing Token Rotation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_token = _walk_config(snapshot.config_raw or {}, _TOKEN_KEYS)
        if not has_token:
            return []
        has_rotation = _walk_config(snapshot.config_raw or {}, _ROTATION_KEYS)
        if not has_rotation:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="token.rotation",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has token configuration but no token "
                        f"rotation or refresh mechanism. Compromised tokens remain valid"
                        f"indefinitely."
                    ),
                    evidence="No rotation/refresh keys found in token configuration",
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
                resource_name="token.rotation",
                status_extended=(
                    f"Server '{snapshot.server_name}' token configuration includesrotation/refresh."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
