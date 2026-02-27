"""SESS005: Missing Session Invalidation on Logout.

Detects MCP servers that fail to properly invalidate sessions when a user or LLM client
disconnects or logs out. Without explicit session invalidation, session tokens remain valid on
the server side even after the client believes the session has ended, creating a window for
session reuse attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_store", "session_id"}
_INVALIDATION_KEYS = {
    "invalidate",
    "destroy",
    "end_session",
    "revoke",
    "logout",
    "session_destroy",
    "clear_session",
    "session_invalidation",
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


class MissingSessionInvalidationCheck(BaseCheck):
    """Missing Session Invalidation on Logout."""

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
        has_invalidation = _walk_config(snapshot.config_raw or {}, _INVALIDATION_KEYS)
        if not has_invalidation:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.invalidation",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no session invalidation mechanism. "
                        f"Sessions remain active after logout or auth failure."
                    ),
                    evidence="No invalidate/destroy/end_session configuration found",
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
                resource_name="session.invalidation",
                status_extended=(
                    f"Server '{snapshot.server_name}' has session invalidation configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
