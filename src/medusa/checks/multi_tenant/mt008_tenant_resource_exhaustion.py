"""MT008: Tenant Resource Exhaustion.

Detects MCP servers that do not enforce per-tenant resource quotas, allowing a single tenant to
monopolize shared server resources including CPU, memory, network bandwidth, storage, and
database connections, causing denial of service for other tenants.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.multi_tenant.mt001_missing_tenant_isolation import _mt_config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_TENANT_QUOTA_KEYS = {
    "tenant_quota",
    "per_tenant_limit",
    "tenant_resource_limit",
    "tenant_rate_limit",
    "tenant_throttle",
    "tenant_cpu_limit",
    "tenant_memory_limit",
}


class TenantResourceExhaustionCheck(BaseCheck):
    """Tenant Resource Exhaustion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _mt_config_check(
            snapshot,
            meta,
            config_keys=_TENANT_QUOTA_KEYS,
            missing_msg=(
                "Server '{server}' has no per-tenant resource quota configuration. "
                "A single tenant can monopolize resources for all others."
            ),
            present_msg="Server '{server}' has per-tenant resource quotas configured.",
        )
