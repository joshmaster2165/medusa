"""SAMP015: Sampling System Prompt Override.

Detects MCP server sampling requests that attempt to override or modify the LLM client's system
prompt. By injecting a custom system prompt through sampling, a malicious server can
fundamentally alter the LLM's behavior, remove safety constraints, and redirect the agent toward
attacker-controlled objectives.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SamplingSystemPromptOverrideCheck(BaseCheck):
    """Sampling System Prompt Override."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp015 check logic
        return []
