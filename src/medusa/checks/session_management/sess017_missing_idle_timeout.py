"""SESS017: Missing Idle Session Timeout.

Detects MCP server sessions that lack idle timeout configuration. Without idle timeouts,
sessions remain active even when no tool invocations or client interactions have occurred for
extended periods. This leaves sessions open for exploitation during periods of user inactivity.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_store", "session_id"}
_IDLE_KEYS = {
    "idle_timeout",
    "inactivity_timeout",
    "idle_ttl",
    "activity_timeout",
    "session_idle",
    "max_idle",
    "idle_expire",
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


class MissingIdleTimeoutCheck(BaseCheck):
    """Missing Idle Session Timeout."""

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
        has_idle = _walk_config(snapshot.config_raw or {}, _IDLE_KEYS)
        if not has_idle:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.idle_timeout",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no idle session timeout. "
                        f"Inactive sessions remain open indefinitely."
                    ),
                    evidence="No idle_timeout/inactivity_timeout configuration found",
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
                resource_name="session.idle_timeout",
                status_extended=(
                    f"Server '{snapshot.server_name}' has idle session timeout configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
