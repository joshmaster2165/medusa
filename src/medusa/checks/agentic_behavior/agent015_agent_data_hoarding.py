"""AGENT015: Agent Data Hoarding.

Detects MCP configurations where agents collect, store, or retain more data than necessary for
their current task. Data hoarding increases the value of a compromised session and violates data
minimization principles required by privacy regulations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class AgentDataHoardingCheck(BaseCheck):
    """Agent Data Hoarding."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent015 check logic
        return []
