"""SESS001: Missing Session Timeout.

Detects MCP server configurations that lack session timeout settings for client connections.
When sessions between LLM clients and MCP servers persist indefinitely, abandoned or forgotten
sessions remain active and exploitable. Tool invocations can continue on stale sessions long
after the user has disengaged.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSessionTimeoutCheck(BaseCheck):
    """Missing Session Timeout."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess001 check logic
        return []
