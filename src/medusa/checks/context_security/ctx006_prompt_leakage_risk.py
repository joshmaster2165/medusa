"""CTX006: System Prompt Leakage Risk.

Detects MCP tool behaviors or output patterns that could cause the LLM to reveal its system
prompt or internal instructions. System prompt leakage exposes security controls and business
logic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PromptLeakageRiskCheck(BaseCheck):
    """System Prompt Leakage Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ctx006 check logic
        return []
