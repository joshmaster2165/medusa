"""MT004: Missing Tenant Context Validation.

Detects MCP server requests that are processed without validating the tenant context, or where
the tenant identifier is derived from client-supplied data without verification. Missing tenant
context validation allows clients to operate outside their authorized tenant scope.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingTenantContextCheck(BaseCheck):
    """Missing Tenant Context Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement mt004 check logic
        return []
