"""SESS007: Session Replay Attack Risk.

Detects MCP server configurations vulnerable to session replay attacks where captured session
tokens or authenticated requests can be retransmitted to gain unauthorized access. Without
replay protections such as nonces or timestamp validation, intercepted tool invocation requests
can be replayed by an attacker.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "token", "auth"}
_REPLAY_PROTECT_KEYS = {
    "nonce",
    "replay_protection",
    "timestamp_validation",
    "jti",
    "request_id",
    "idempotency_key",
    "anti_replay",
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


class SessionReplayRiskCheck(BaseCheck):
    """Session Replay Attack Risk."""

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
        has_protection = _walk_config(snapshot.config_raw or {}, _REPLAY_PROTECT_KEYS)
        if not has_protection:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.replay_protection",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no session replay protection. "
                        f"Captured tokens can be replayed to invoke tools without authorization."
                    ),
                    evidence="No nonce/jti/replay_protection configuration found",
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
                resource_name="session.replay_protection",
                status_extended=(
                    f"Server '{snapshot.server_name}' has replay protection configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
