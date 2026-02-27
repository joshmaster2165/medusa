"""AGENT009: Reward Hacking.

Detects MCP configurations where an attacker can exploit the agent's reward or feedback
mechanisms to reinforce undesired behavior. By manipulating success signals, error messages, or
feedback loops, an attacker can train the agent to prefer malicious tools or follow harmful
patterns.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class RewardHackingCheck(BaseCheck):
    """Reward Hacking."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent009 check logic
        return []
