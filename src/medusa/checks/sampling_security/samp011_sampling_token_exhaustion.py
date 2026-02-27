"""SAMP011: Sampling Token Exhaustion.

Detects MCP server configurations where sampling requests can consume excessive LLM tokens
through large prompts, high max_tokens values, or frequent requests. Token exhaustion creates a
denial-of-service condition for the user's LLM quota and can result in significant financial
costs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SamplingTokenExhaustionCheck(BaseCheck):
    """Sampling Token Exhaustion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp011 check logic
        return []
