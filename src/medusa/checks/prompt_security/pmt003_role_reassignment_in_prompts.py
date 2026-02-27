"""PMT003: Role Reassignment in Prompts.

Detects MCP prompt definitions that attempt to reassign the LLM role, override system
instructions, or establish new behavioral constraints. Prompts containing phrases like "you are
now" or "ignore previous instructions" can manipulate LLM identity.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class RoleReassignmentInPromptsCheck(BaseCheck):
    """Role Reassignment in Prompts."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement pmt003 check logic
        return []
