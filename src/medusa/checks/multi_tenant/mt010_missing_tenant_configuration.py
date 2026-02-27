"""MT010: Missing Tenant Configuration Isolation.

Detects MCP servers where tenant-specific configuration such as security policies, feature
flags, access controls, and operational parameters is stored in shared configuration without
proper isolation. Configuration bleed between tenants can alter security posture unexpectedly.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.multi_tenant.mt001_missing_tenant_isolation import _mt_config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_TENANT_CONFIG_KEYS = {
    "tenant_config",
    "per_tenant_config",
    "tenant_settings",
    "tenant_feature_flags",
    "tenant_config_isolation",
}


class MissingTenantConfigurationCheck(BaseCheck):
    """Missing Tenant Configuration Isolation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _mt_config_check(
            snapshot,
            meta,
            config_keys=_TENANT_CONFIG_KEYS,
            missing_msg=(
                "Server '{server}' has no tenant configuration isolation. "
                "Shared config may cause security posture to bleed between tenants."
            ),
            present_msg="Server '{server}' has per-tenant configuration isolation.",
        )
