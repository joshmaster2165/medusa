"""MT006: Shared Credential Store.

Detects MCP servers that store credentials for multiple tenants in a shared credential store
without proper encryption and access controls per tenant. A shared credential store creates a
single point of compromise that exposes all tenant credentials.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.multi_tenant.mt001_missing_tenant_isolation import _mt_config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_CRED_ISOLATION_KEYS = {
    "tenant_credentials",
    "per_tenant_secrets",
    "credential_isolation",
    "tenant_secret_store",
    "tenant_vault",
    "per_tenant_keys",
}


class SharedCredentialStoreCheck(BaseCheck):
    """Shared Credential Store."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _mt_config_check(
            snapshot,
            meta,
            config_keys=_CRED_ISOLATION_KEYS,
            missing_msg=(
                "Server '{server}' has no per-tenant credential store configuration. "
                "A shared credential store creates a single point of compromise."
            ),
            present_msg="Server '{server}' has per-tenant credential isolation configured.",
        )
