"""SESS020: WebSocket Session Security.

Detects MCP servers using WebSocket transport without proper session security controls.
WebSocket connections used for MCP communication may lack authentication token validation on
upgrade, origin checking, or per-message session verification, allowing unauthorized access to
tool invocations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_WS_KEYS = {"websocket", "ws", "websocket_url", "ws_url"}
_WS_SECURITY_KEYS = {
    "origin_check",
    "check_origin",
    "ws_auth",
    "websocket_auth",
    "ws_token",
    "handshake_auth",
    "ws_origin",
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


def _has_ws_url(config: dict, depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if isinstance(v, str) and v.startswith("ws://"):
            return True
        if isinstance(v, dict) and _has_ws_url(v, depth + 1):
            return True
    return False


class WebsocketSessionSecurityCheck(BaseCheck):
    """WebSocket Session Security."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_ws = _walk_config(snapshot.config_raw or {}, _WS_KEYS) or _has_ws_url(
            snapshot.config_raw or {}
        )
        if not has_ws:
            return []
        has_ws_security = _walk_config(snapshot.config_raw or {}, _WS_SECURITY_KEYS)
        if not has_ws_security:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="websocket.security",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses WebSocket without session security "
                        f"controls (origin check, handshake auth). Unauthorized connections"
                        f"possible."
                    ),
                    evidence="WebSocket config present but no origin_check/ws_auth configuration",
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
                resource_name="websocket.security",
                status_extended=(
                    f"Server '{snapshot.server_name}' WebSocket has session security controls."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
