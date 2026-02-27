"""SAMP013: Model Selection Manipulation.

Detects MCP server sampling requests that attempt to control which LLM model processes the
request. By specifying a weaker or more permissive model, an attacker can bypass safety
guardrails implemented in the user's preferred model and obtain responses that would otherwise
be blocked.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ModelSelectionManipulationCheck(BaseCheck):
    """Model Selection Manipulation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp013 check logic
        return []
