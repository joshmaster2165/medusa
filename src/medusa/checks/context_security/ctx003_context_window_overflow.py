"""CTX003: Context Window Overflow Attack.

Detects MCP tool outputs or resource contents designed to flood the LLM context window with
excessive data. Context window overflow attacks push legitimate instructions out of the context,
causing the LLM to lose track of its original directives.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ContextWindowOverflowCheck(BaseCheck):
    """Context Window Overflow Attack."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ctx003 check logic
        return []
