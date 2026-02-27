"""AGENT005: Delegation Without Authorization.

Detects MCP configurations where one LLM agent can delegate tasks to other agents or sub-agents
without proper authorization checks. In multi-agent architectures, delegation without
authorization allows a compromised agent to leverage other agents' capabilities and access
rights.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DelegationWithoutAuthCheck(BaseCheck):
    """Delegation Without Authorization."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent005 check logic
        return []
