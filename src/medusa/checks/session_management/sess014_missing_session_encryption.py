"""SESS014: Missing Session Encryption.

Detects MCP server sessions where session data is stored or transmitted without encryption.
Unencrypted session tokens and session state can be intercepted in transit or read from storage
by attackers with access to network traffic or the storage medium.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_store", "session_data"}
_ENCRYPTION_KEYS = {
    "encrypt",
    "encryption",
    "encrypted",
    "cipher",
    "aes",
    "session_encryption",
    "secure_store",
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


class MissingSessionEncryptionCheck(BaseCheck):
    """Missing Session Encryption."""

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
        has_encryption = _walk_config(snapshot.config_raw or {}, _ENCRYPTION_KEYS)
        if not has_encryption:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.encryption",
                    status_extended=(
                        f"Server '{snapshot.server_name}' session data may not be encrypted. "
                        f"Session state can be read from storage or network traffic."
                    ),
                    evidence="No encrypt/cipher/encryption configuration found in session config",
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
                resource_name="session.encryption",
                status_extended=(
                    f"Server '{snapshot.server_name}' has session encryption configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
