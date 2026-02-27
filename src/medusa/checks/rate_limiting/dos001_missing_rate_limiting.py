"""DOS001: Missing Rate Limiting.

Detects MCP server configurations that lack rate limiting on tool invocations. Without rate
limits, an attacker or compromised LLM agent can invoke tools at an unlimited rate, overwhelming
the server and any downstream services the tools interact with.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingRateLimitingCheck(BaseCheck):
    """Missing Rate Limiting."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dos001 check logic
        return []
