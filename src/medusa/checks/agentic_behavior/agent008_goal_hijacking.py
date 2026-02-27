"""AGENT008: Goal Hijacking.

Detects MCP configurations where the agent's primary goal or task can be redirected through
prompt injection in tool outputs, resource contents, or sampling responses. Goal hijacking
causes the agent to abandon the user's intended task and pursue an attacker-defined objective.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class GoalHijackingCheck(BaseCheck):
    """Goal Hijacking."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent008 check logic
        return []
