"""SM012: Missing Secret Revocation.

Detects MCP servers that lack the ability to immediately revoke secrets when they are
compromised. Without revocation capability, compromised secrets remain valid until they expire
naturally, which may be never for long-lived credentials.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_REVOCATION_KEYS = {
    "revoke",
    "revocation",
    "invalidate",
    "revoke_endpoint",
    "token_revocation",
    "revocation_endpoint",
    "blacklist",
    "denylist",
    "blocklist",
}


class MissingSecretRevocationCheck(BaseCheck):
    """Missing Secret Revocation."""

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
            if leaf in _REVOCATION_KEYS:
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
                        f"No secret revocation configuration found for server "
                        f"'{snapshot.server_name}'. Secrets should be revocable on compromise."
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
                    f"Secret revocation configuration detected for server '{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
