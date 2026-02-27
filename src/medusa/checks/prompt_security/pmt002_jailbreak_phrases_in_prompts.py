"""PMT002: Jailbreak Phrases in Prompt Definitions.

Detects MCP prompt definitions that contain known jailbreak phrases or patterns designed to
bypass LLM safety guardrails. These phrases include role-play triggers, instruction override
patterns, and constraint removal commands embedded in server-defined prompts.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class JailbreakPhrasesInPromptsCheck(BaseCheck):
    """Jailbreak Phrases in Prompt Definitions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement pmt002 check logic
        return []
