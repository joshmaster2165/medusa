"""CTX008: Token Budget Exhaustion.

Detects MCP tools that return excessively large responses that consume a disproportionate share
of the available token budget. Token budget exhaustion degrades LLM performance and increases
costs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class TokenBudgetExhaustionCheck(BaseCheck):
    """Token Budget Exhaustion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ctx008 check logic
        return []
