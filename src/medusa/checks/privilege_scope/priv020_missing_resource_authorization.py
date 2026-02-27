"""PRIV020: Missing Resource Authorization.

Detects MCP resources that can be accessed without authorization checks. Resources without
access control allow any authenticated user to read, modify, or delete any resource regardless
of ownership or permissions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingResourceAuthorizationCheck(BaseCheck):
    """Missing Resource Authorization."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement priv020 check logic
        return []
