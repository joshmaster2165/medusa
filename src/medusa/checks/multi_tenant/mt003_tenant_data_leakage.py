"""MT003: Tenant Data Leakage.

Detects MCP server responses, error messages, logs, or metadata that leak data belonging to one
tenant to another tenant. Data leakage can occur through shared error handlers, common log
streams, cached responses, or improperly scoped query results.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.multi_tenant.mt001_missing_tenant_isolation import _mt_config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_LEAKAGE_PREVENTION_KEYS = {
    "data_isolation",
    "tenant_data_filter",
    "row_level_security",
    "data_scoping",
    "tenant_filter",
    "rls",
    "data_boundary",
}


class TenantDataLeakageCheck(BaseCheck):
    """Tenant Data Leakage."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _mt_config_check(
            snapshot,
            meta,
            config_keys=_LEAKAGE_PREVENTION_KEYS,
            missing_msg=(
                "Server '{server}' has no tenant data isolation configuration. "
                "Responses or errors may leak data across tenant boundaries."
            ),
            present_msg="Server '{server}' has tenant data isolation configuration.",
        )
