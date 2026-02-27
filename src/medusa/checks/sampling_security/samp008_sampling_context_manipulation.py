"""SAMP008: Sampling Context Manipulation.

Detects MCP server implementations where sampling requests can manipulate the LLM's context
window by injecting or modifying the conversation history, system prompts, or tool outputs
available during sampling. Context manipulation can alter the LLM's understanding of the current
task and available information.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SamplingContextManipulationCheck(BaseCheck):
    """Sampling Context Manipulation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp008 check logic
        return []
