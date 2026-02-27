"""AUTH022: Missing Token Revocation.

Detects MCP server configurations without a mechanism to revoke compromised or unused tokens.
Without revocation, compromised tokens remain valid until they expire, which may be a long time
or never.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_TOKEN_KEYS = {"jwt", "token", "access_token", "auth", "api_key", "apikey"}
_REVOCATION_KEYS = {
    "revocation",
    "revoke",
    "blacklist",
    "blocklist",
    "denylist",
    "token_blacklist",
    "revocation_endpoint",
    "introspection",
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


class MissingTokenRevocationCheck(BaseCheck):
    """Missing Token Revocation."""

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
        has_revocation = _walk_config(snapshot.config_raw or {}, _REVOCATION_KEYS)
        if not has_revocation:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="token.revocation",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no token revocation mechanism. "
                        f"Compromised tokens cannot be invalidated before expiry."
                    ),
                    evidence="No revocation/blacklist/denylist configuration found",
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
                resource_name="token.revocation",
                status_extended=(
                    f"Server '{snapshot.server_name}' has token revocation configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
