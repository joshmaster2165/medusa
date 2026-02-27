"""AGENT003: Agent Loop Detection.

Detects MCP configurations that lack detection and prevention mechanisms for infinite tool
invocation loops. Without loop detection, an LLM agent can repeatedly invoke the same tool or
cycle through a set of tools indefinitely, consuming resources and potentially causing
unintended side effects.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class AgentLoopDetectionCheck(BaseCheck):
    """Agent Loop Detection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent003 check logic
        return []
