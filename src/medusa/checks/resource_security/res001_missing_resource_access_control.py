"""RES001: Missing Resource Access Control.

Detects MCP resource endpoints that lack access control checks, allowing any authenticated or
unauthenticated client to read, list, or subscribe to resources without authorization
verification. Resources may contain sensitive data that should be restricted by role or scope.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingResourceAccessControlCheck(BaseCheck):
    """Missing Resource Access Control."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res001 check logic
        return []
