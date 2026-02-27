"""CTX009: Role Confusion Attack.

Detects MCP tool outputs containing content designed to confuse the LLM's understanding of
message roles (system, user, assistant, tool). Role confusion can trick the LLM into treating
tool output as system instructions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class RoleConfusionAttackCheck(BaseCheck):
    """Role Confusion Attack."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ctx009 check logic
        return []
