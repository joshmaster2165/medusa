"""DOS002: Missing Request Throttling.

Detects MCP server API endpoints that lack request throttling mechanisms. Without throttling,
burst traffic from LLM agents can saturate server capacity, degrading performance for all
connected clients and potentially causing service outages.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingRequestThrottlingCheck(BaseCheck):
    """Missing Request Throttling."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dos002 check logic
        return []
