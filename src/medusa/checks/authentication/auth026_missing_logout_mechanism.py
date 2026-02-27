"""AUTH026: Missing Logout Mechanism.

Detects MCP server configurations without a mechanism to invalidate active sessions or tokens on
logout. Without logout functionality, users cannot terminate their sessions, leaving them
vulnerable to session hijacking and unauthorized reuse.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "auth", "token", "jwt"}
_LOGOUT_KEYS = {
    "logout",
    "signout",
    "sign_out",
    "end_session",
    "logout_url",
    "logout_endpoint",
    "session_end",
    "invalidate",
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


class MissingLogoutMechanismCheck(BaseCheck):
    """Missing Logout Mechanism."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_session = _walk_config(snapshot.config_raw or {}, _SESSION_KEYS)
        if not has_session:
            return []
        has_logout = _walk_config(snapshot.config_raw or {}, _LOGOUT_KEYS)
        # Also check capabilities for logout
        caps = snapshot.capabilities or {}
        if not has_logout and not any("logout" in str(v).lower() for v in caps.values()):
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="auth.logout",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no logout or session-end mechanism. "
                        f"Active sessions cannot be terminated by the user."
                    ),
                    evidence="No logout/signout/end_session configuration found",
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
                resource_name="auth.logout",
                status_extended=(
                    f"Server '{snapshot.server_name}' has a logout mechanism configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
