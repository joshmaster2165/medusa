"""SM004: Missing Vault Integration.

Detects MCP servers that manage secrets directly rather than using a dedicated secrets
management service or vault. Direct secret management lacks the encryption, access control,
audit logging, and rotation capabilities that purpose-built vault systems provide.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.credentials import VAULT_CONFIG_KEYS


def _has_vault_config(config: dict, env: dict) -> bool:
    for key, _value in _flatten_config(config):
        leaf = key.split(".")[-1].split("[")[0].lower()
        if leaf in VAULT_CONFIG_KEYS:
            return True
    for var in env:
        if var.lower() in VAULT_CONFIG_KEYS:
            return True
    return False


class MissingVaultIntegrationCheck(BaseCheck):
    """Missing Vault Integration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if not snapshot.config_raw and not snapshot.env:
            return []

        found = _has_vault_config(snapshot.config_raw or {}, snapshot.env)
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
                        f"No vault or secrets manager integration detected for server "
                        f"'{snapshot.server_name}'. Secrets should be stored in a vault."
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
                    f"Vault or secrets manager integration detected for server "
                    f"'{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
