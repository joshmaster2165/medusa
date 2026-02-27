"""AUTH026: Missing Logout Mechanism.

Detects MCP server configurations without a mechanism to invalidate active sessions or tokens on
logout. Without logout functionality, users cannot terminate their sessions, leaving them
vulnerable to session hijacking and unauthorized reuse.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingLogoutMechanismCheck(BaseCheck):
    """Missing Logout Mechanism."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth026 check logic
        return []
