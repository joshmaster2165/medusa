"""SESS002: Session Fixation Vulnerability.

Detects MCP server implementations vulnerable to session fixation attacks where an attacker can
force a known session ID onto a victim's LLM client connection. If the server accepts externally
supplied session identifiers without regeneration after authentication, an attacker can pre-set
the session ID and then hijack the authenticated session.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_id", "session_cookie"}
_REGEN_KEYS = {
    "regenerate",
    "regenerate_session",
    "session_regeneration",
    "rotate_on_login",
    "new_session_on_auth",
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


class SessionFixationCheck(BaseCheck):
    """Session Fixation Vulnerability."""

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
        has_regen = _walk_config(snapshot.config_raw or {}, _REGEN_KEYS)
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
                    resource_name="session.fixation",
                    status_extended=(
                        f"Server '{snapshot.server_name}' session configuration lacks session ID "
                        f"regeneration, leaving it vulnerable to session fixation attacks."
                    ),
                    evidence="Session config found but no regeneration setting detected",
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
                resource_name="session.fixation",
                status_extended=(
                    f"Server '{snapshot.server_name}' has session ID regeneration configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
