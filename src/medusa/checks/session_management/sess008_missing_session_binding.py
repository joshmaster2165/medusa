"""SESS008: Missing Session-IP Binding.

Detects MCP server sessions that are not bound to the originating client IP address or other
client fingerprint. Without session binding, a session token stolen from one network location
can be used from any other location to invoke tools and access resources on the MCP server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_store", "session_id"}
_BINDING_KEYS = {
    "ip_binding",
    "session_binding",
    "client_binding",
    "bind_to_ip",
    "ip_validation",
    "fingerprint",
    "user_agent_binding",
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


class MissingSessionBindingCheck(BaseCheck):
    """Missing Session-IP Binding."""

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
        has_binding = _walk_config(snapshot.config_raw or {}, _BINDING_KEYS)
        if not has_binding:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.binding",
                    status_extended=(
                        f"Server '{snapshot.server_name}' session is not bound to client IP or "
                        f"fingerprint. Stolen tokens can be used from any location."
                    ),
                    evidence="No ip_binding/fingerprint/session_binding configuration found",
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
                resource_name="session.binding",
                status_extended=(
                    f"Server '{snapshot.server_name}' has session client binding configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
