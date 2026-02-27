"""HARD005: Admin Interface Exposed.

Detects MCP servers that expose administrative or management interfaces to the same network or
transport as client-facing endpoints. Admin interfaces provide elevated capabilities including
server configuration, user management, and diagnostic access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class AdminInterfaceExposedCheck(BaseCheck):
    """Admin Interface Exposed."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard005 check logic
        return []
