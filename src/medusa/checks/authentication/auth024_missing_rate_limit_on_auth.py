"""AUTH024: Missing Rate Limit on Auth Endpoints.

Detects authentication endpoints without rate limiting or brute-force protection. Endpoints that
accept unlimited authentication attempts allow attackers to perform credential stuffing and
brute-force attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_RATE_LIMIT_KEYS = {
    "rate_limit",
    "ratelimit",
    "throttle",
    "throttling",
    "max_attempts",
    "lockout",
    "backoff",
    "cooldown",
    "brute_force_protection",
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


class MissingRateLimitOnAuthCheck(BaseCheck):
    """Missing Rate Limit on Auth Endpoints."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_rate_limit = _walk_config(snapshot.config_raw or {}, _RATE_LIMIT_KEYS)
        if not has_rate_limit:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="auth.rate_limit",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no rate limiting on authentication. "
                        f"Brute-force and credential stuffing attacks are unrestricted."
                    ),
                    evidence="No rate_limit/throttle/max_attempts configuration found",
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
                resource_name="auth.rate_limit",
                status_extended=(
                    f"Server '{snapshot.server_name}' has authentication rate limiting configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
