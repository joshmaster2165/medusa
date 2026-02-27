"""SESS009: Session Data Exposure.

Detects MCP server implementations that store sensitive data directly in session objects or
transmit session contents to the client. Session data may include tool invocation history, user
credentials, resource URIs, or intermediate computation results that should not be exposed to
the LLM client or stored in client-accessible session storage.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_data", "session_store"}
_SENSITIVE_DATA_KEYS = {
    "password",
    "secret",
    "token",
    "credential",
    "private_key",
    "api_key",
    "ssn",
    "credit_card",
    "pii",
}


def _session_stores_sensitive(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in {"session_data", "session_store"} and isinstance(v, dict):
            for sk in v:
                if sk.lower() in _SENSITIVE_DATA_KEYS:
                    return f"Sensitive key '{sk}' found in session data"
        if isinstance(v, dict):
            result = _session_stores_sensitive(v, depth + 1)
            if result:
                return result
    return None


class SessionDataExposureCheck(BaseCheck):
    """Session Data Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence = _session_stores_sensitive(snapshot.config_raw or {})
        if evidence:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.data",
                    status_extended=(
                        f"Server '{snapshot.server_name}' stores sensitive data in session objects "
                        f"that may be exposed to clients or logged."
                    ),
                    evidence=evidence,
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
                resource_name="session.data",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to store sensitive data"
                    f"in sessions."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
