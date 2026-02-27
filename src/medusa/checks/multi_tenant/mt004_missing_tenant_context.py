"""MT004: Missing Tenant Context Validation.

Detects MCP server requests that are processed without validating the tenant context, or where
the tenant identifier is derived from client-supplied data without verification. Missing tenant
context validation allows clients to operate outside their authorized tenant scope.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.multi_tenant.mt001_missing_tenant_isolation import _mt_config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_CONTEXT_VALIDATION_KEYS = {
    "tenant_context_validation",
    "tenant_verification",
    "tenant_claim",
    "tenant_assertion",
    "validate_tenant",
    "tenant_auth",
    "tenant_token_validation",
}


class MissingTenantContextCheck(BaseCheck):
    """Missing Tenant Context Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _mt_config_check(
            snapshot,
            meta,
            config_keys=_CONTEXT_VALIDATION_KEYS,
            missing_msg=(
                "Server '{server}' has no tenant context validation configuration. "
                "Requests may be processed without verifying the tenant identity."
            ),
            present_msg="Server '{server}' has tenant context validation configuration.",
        )
