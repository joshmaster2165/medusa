"""SESS017: Missing Idle Session Timeout.

Detects MCP server sessions that lack idle timeout configuration. Without idle timeouts,
sessions remain active even when no tool invocations or client interactions have occurred for
extended periods. This leaves sessions open for exploitation during periods of user inactivity.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingIdleTimeoutCheck(BaseCheck):
    """Missing Idle Session Timeout."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess017 check logic
        return []
