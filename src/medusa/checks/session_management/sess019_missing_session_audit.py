"""SESS019: Missing Session Audit Trail.

Detects MCP server deployments that do not maintain an audit trail of session lifecycle events
including creation, authentication, tool invocations, privilege changes, and termination.
Without session auditing, security incidents involving compromised sessions cannot be
investigated or detected.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_store"}
_AUDIT_KEYS = {
    "audit",
    "session_audit",
    "audit_log",
    "session_logging",
    "access_log",
    "event_log",
    "audit_trail",
    "session_events",
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


class MissingSessionAuditCheck(BaseCheck):
    """Missing Session Audit Trail."""

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
        has_audit = _walk_config(snapshot.config_raw or {}, _AUDIT_KEYS)
        if not has_audit:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.audit",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no session audit trail. "
                        f"Session compromise cannot be detected or investigated."
                    ),
                    evidence="No audit/session_audit/audit_log configuration found",
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
                resource_name="session.audit",
                status_extended=(
                    f"Server '{snapshot.server_name}' has session audit logging configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
