"""SESS006: Missing Concurrent Session Limit.

Detects MCP server configurations that allow unlimited concurrent sessions for a single user or
identity. Without concurrent session limits, a compromised credential can be used to establish
multiple parallel sessions across different LLM clients without the legitimate user being aware.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_store"}
_LIMIT_KEYS = {
    "max_sessions",
    "concurrent_sessions",
    "session_limit",
    "max_concurrent",
    "simultaneous_sessions",
    "session_count_limit",
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


class ConcurrentSessionLimitCheck(BaseCheck):
    """Missing Concurrent Session Limit."""

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
        has_limit = _walk_config(snapshot.config_raw or {}, _LIMIT_KEYS)
        if not has_limit:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.concurrent_limit",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no concurrent session limit. "
                        f"Compromised credentials can establish unlimited parallel sessions."
                    ),
                    evidence="No max_sessions/session_limit configuration found",
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
                resource_name="session.concurrent_limit",
                status_extended=(
                    f"Server '{snapshot.server_name}' has concurrent session limit configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
