"""DOS004: Missing Concurrent Request Limit.

Detects MCP server configurations that allow unlimited concurrent requests from a single client
or across all clients. Without concurrent request limits, server threads, connections, and
processing capacity can be exhausted by parallel requests from aggressive LLM agents.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ConcurrentRequestLimitCheck(BaseCheck):
    """Missing Concurrent Request Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dos004 check logic
        return []
