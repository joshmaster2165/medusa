"""SESS010: Missing Session ID Rotation.

Detects MCP servers that do not periodically rotate session identifiers during active sessions.
Without rotation, a session ID remains static for the entire session lifetime, giving attackers
an extended window to capture and exploit the token for unauthorized tool invocations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.session import SESSION_SECURITY_KEYS

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_store", "session_id", "session_cookie"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class MissingSessionRotationCheck(BaseCheck):
    """Missing Session ID Rotation."""

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
        has_rotation = _walk_config(snapshot.config_raw or {}, SESSION_SECURITY_KEYS)
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
                    resource_name="session.rotation",
                    status_extended=(
                        f"Server '{snapshot.server_name}' does not rotate session IDs. "
                        f"Static session tokens extend the attack window if captured."
                    ),
                    evidence="No rotate/regenerate/rotation configuration found",
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
                resource_name="session.rotation",
                status_extended=(
                    f"Server '{snapshot.server_name}' has session ID rotation configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
