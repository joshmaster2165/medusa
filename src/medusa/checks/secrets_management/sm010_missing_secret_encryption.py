"""SM010: Missing Secret Encryption at Rest.

Detects MCP servers that store secrets without encrypting them at rest. Unencrypted secret
storage means that physical access to the storage medium, database dumps, or backup files
directly exposes all stored secrets in plaintext.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_ENCRYPTION_AT_REST_KEYS = {
    "encryption_at_rest",
    "encrypt_at_rest",
    "encrypted_storage",
    "secret_encryption",
    "kms",
    "kms_key",
    "kms_key_id",
    "encrypt_secrets",
    "secrets_encrypted",
}


class MissingSecretEncryptionCheck(BaseCheck):
    """Missing Secret Encryption at Rest."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if not snapshot.config_raw:
            return []

        found = False
        for key, _value in _flatten_config(snapshot.config_raw):
            leaf = key.split(".")[-1].split("[")[0].lower()
            if leaf in _ENCRYPTION_AT_REST_KEYS:
                found = True
                break
        for var in snapshot.env:
            if var.lower() in _ENCRYPTION_AT_REST_KEYS:
                found = True
                break

        if not found:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name=snapshot.config_file_path or "config",
                    status_extended=(
                        f"No encryption-at-rest configuration detected for server "
                        f"'{snapshot.server_name}'. Secrets should be encrypted at rest."
                    ),
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
                resource_name=snapshot.config_file_path or "config",
                status_extended=(
                    f"Encryption-at-rest configuration detected for server'{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
