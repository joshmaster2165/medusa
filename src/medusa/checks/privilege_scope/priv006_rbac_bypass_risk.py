"""PRIV006: RBAC Bypass Risk.

Detects missing role-based access control on tool invocations. MCP servers that do not implement
RBAC allow any authenticated user to invoke any tool, regardless of their role or the
sensitivity of the operation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class RbacBypassRiskCheck(BaseCheck):
    """RBAC Bypass Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement priv006 check logic
        return []
