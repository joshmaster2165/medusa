"""MT005: Tenant Impersonation Risk.

Detects MCP server configurations that allow one tenant to impersonate another through token
manipulation, session hijacking, or exploitation of tenant switching mechanisms. Impersonation
enables full access to the target tenant data and operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.multi_tenant.mt001_missing_tenant_isolation import _mt_config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_IMPERSONATION_PREVENTION_KEYS = {
    "tenant_impersonation_protection",
    "anti_impersonation",
    "tenant_token_binding",
    "tenant_session_binding",
    "prevent_tenant_switch",
    "tenant_mfa",
}


class TenantImpersonationCheck(BaseCheck):
    """Tenant Impersonation Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _mt_config_check(
            snapshot,
            meta,
            config_keys=_IMPERSONATION_PREVENTION_KEYS,
            missing_msg=(
                "Server '{server}' has no tenant impersonation prevention. "
                "Token manipulation may allow one tenant to impersonate another."
            ),
            present_msg="Server '{server}' has tenant impersonation protection configured.",
        )
