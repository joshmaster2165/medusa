"""AUTH025: Session Fixation Risk.

Detects session management implementations that do not regenerate session IDs after successful
authentication. Session fixation allows an attacker to set a known session ID before the user
authenticates, then hijack the session after authentication elevates its privileges.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_id", "session_cookie", "session_store"}
_REGENERATION_KEYS = {
    "regenerate",
    "regenerate_session",
    "session_regeneration",
    "rotate_session",
    "new_session_on_login",
    "fixation_protection",
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


class SessionFixationRiskCheck(BaseCheck):
    """Session Fixation Risk."""

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
        has_regen = _walk_config(snapshot.config_raw or {}, _REGENERATION_KEYS)
        if not has_regen:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.regeneration",
                    status_extended=(
                        f"Server '{snapshot.server_name}' session configuration lacks session ID "
                        f"regeneration after login, enabling session fixation attacks."
                    ),
                    evidence="Session config present but no regeneration/rotate setting found",
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
                resource_name="session.regeneration",
                status_extended=(
                    f"Server '{snapshot.server_name}' has session ID regeneration configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
