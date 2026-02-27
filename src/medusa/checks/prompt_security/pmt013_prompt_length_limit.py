"""PMT013: Missing Prompt Length Limit.

Detects MCP prompt definitions and argument schemas that do not enforce length limits on prompt
content or argument values. Without length limits, extremely long prompts can exhaust LLM
context windows, increase processing costs, and enable injection through context overflow.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PromptLengthLimitCheck(BaseCheck):
    """Missing Prompt Length Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement pmt013 check logic
        return []
