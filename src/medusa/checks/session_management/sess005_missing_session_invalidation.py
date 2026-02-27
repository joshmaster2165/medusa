"""SESS005: Missing Session Invalidation on Logout.

Detects MCP servers that fail to properly invalidate sessions when a user or LLM client
disconnects or logs out. Without explicit session invalidation, session tokens remain valid on
the server side even after the client believes the session has ended, creating a window for
session reuse attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSessionInvalidationCheck(BaseCheck):
    """Missing Session Invalidation on Logout."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess005 check logic
        return []
