"""MT007: Missing Tenant-Specific Audit.

Detects MCP servers that lack tenant-specific audit logging, making it impossible to track which
tenant performed which operations. Without tenant-scoped audit trails, security incidents cannot
be properly investigated and tenant compliance requirements are unmet.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.multi_tenant.mt001_missing_tenant_isolation import _mt_config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_TENANT_AUDIT_KEYS = {
    "tenant_audit",
    "tenant_audit_log",
    "per_tenant_audit",
    "tenant_activity_log",
    "tenant_event_log",
}


class MissingTenantAuditCheck(BaseCheck):
    """Missing Tenant-Specific Audit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _mt_config_check(
            snapshot,
            meta,
            config_keys=_TENANT_AUDIT_KEYS,
            missing_msg=(
                "Server '{server}' has no tenant-specific audit log configuration. "
                "Security incidents cannot be attributed to specific tenants."
            ),
            present_msg="Server '{server}' has tenant-specific audit logging configured.",
        )
