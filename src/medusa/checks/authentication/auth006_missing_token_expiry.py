"""AUTH006: Missing Token Expiration.

Detects JWT tokens and API keys without expiration claims or time-to-live settings. Tokens that
never expire remain valid indefinitely, even after the user's access should have been revoked or
the token has been compromised.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_EXPIRY_KEYS = {"expiry", "expiration", "exp", "ttl", "max_age", "expires_in", "lifetime"}
_JWT_KEYS = {"jwt", "token", "access_token", "auth"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class MissingTokenExpiryCheck(BaseCheck):
    """Missing Token Expiration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_jwt = _walk_config(snapshot.config_raw or {}, _JWT_KEYS)
        if not has_jwt:
            return []
        has_expiry = _walk_config(snapshot.config_raw or {}, _EXPIRY_KEYS)
        if not has_expiry:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="token.expiry",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has token/JWT configuration "
                        f"without any expiry or TTL setting. Tokens will never expire."
                    ),
                    evidence="No expiry/ttl/max_age key found in token config",
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
                resource_name="token.expiry",
                status_extended=(
                    f"Server '{snapshot.server_name}' token configuration includes expiry settings."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
