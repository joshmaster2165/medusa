"""MT001: Missing Tenant Isolation.

Detects MCP servers that handle multiple tenants without implementing proper isolation between
tenant contexts. Missing isolation allows one tenant operations, data, and tool invocations to
affect or be visible to other tenants sharing the same server instance.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingTenantIsolationCheck(BaseCheck):
    """Missing Tenant Isolation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement mt001 check logic
        return []
