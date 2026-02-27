"""AGENT011: Unbounded Tool Call Count.

Detects MCP configurations that do not limit the number of tool invocations an agent can make
within a single conversation turn or session. Without bounds, an agent can make an unlimited
number of tool calls, consuming resources and potentially causing cumulative harm through
repeated actions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnboundedToolCallsCheck(BaseCheck):
    """Unbounded Tool Call Count."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent011 check logic
        return []
