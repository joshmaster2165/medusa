"""SESS018: Session Deserialization Risk.

Detects MCP server implementations that deserialize session data from untrusted sources without
validation. Insecure deserialization of session objects can lead to remote code execution,
privilege escalation, or denial of service when an attacker crafts malicious serialized session
payloads.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_DESER_RISK_KEYS = {
    "pickle",
    "marshal",
    "java_serialization",
    "php_serialize",
    "deserialize",
    "unserialize",
}
_SAFE_DESER_KEYS = {
    "json",
    "json_only",
    "validate_session",
    "session_hmac",
    "signed_session",
    "session_signature",
}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, str) and v.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class SessionDeserializationRiskCheck(BaseCheck):
    """Session Deserialization Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_risky_deser = _walk_config(snapshot.config_raw or {}, _DESER_RISK_KEYS)
        if has_risky_deser:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.deserialization",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses potentially unsafe session "
                        f"deserialization. Crafted payloads may cause code execution."
                    ),
                    evidence="Risky deserialization format (pickle/marshal/unserialize) detected",
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
                resource_name="session.deserialization",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to use unsafe session"
                    f"deserialization."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
