"""SAMP007: Sampling Without Rate Limit.

Detects MCP server configurations where sampling requests are not subject to rate limiting.
Without rate limits, an MCP server can issue high volumes of sampling requests, consuming LLM
API quotas, increasing costs, and potentially degrading service for the user.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SamplingWithoutRateLimitCheck(BaseCheck):
    """Sampling Without Rate Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp007 check logic
        return []
