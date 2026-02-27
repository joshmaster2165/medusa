"""SESS011: Persistent Session Risk.

Detects MCP server configurations that support persistent or "remember me" sessions that survive
client restarts, browser closures, or system reboots. Persistent sessions extend the window of
exposure for session tokens stored on disk and can be exploited if the client device is
compromised.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_PERSISTENT_KEYS = {
    "remember_me",
    "persistent",
    "keep_alive",
    "permanent_session",
    "long_lived",
    "extended_session",
    "forever",
    "session_persist",
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


class PersistentSessionRiskCheck(BaseCheck):
    """Persistent Session Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_persistent = _walk_config(snapshot.config_raw or {}, _PERSISTENT_KEYS)
        if has_persistent:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.persistent",
                    status_extended=(
                        f"Server '{snapshot.server_name}' supports persistent sessions. "
                        f"Long-lived disk-stored tokens extend the exploitation window."
                    ),
                    evidence="Persistent/remember_me/long_lived session configuration detected",
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
                resource_name="session.persistent",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to use persistent sessions."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
