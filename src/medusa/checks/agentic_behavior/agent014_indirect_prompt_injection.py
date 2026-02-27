"""AGENT014: Indirect Prompt Injection via Tools.

Detects MCP configurations where tool outputs can contain prompt injection payloads that alter
the agent's behavior. When tools return data from external sources such as web pages, files, or
databases, this data may contain hidden instructions that the LLM interprets as commands.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class IndirectPromptInjectionCheck(BaseCheck):
    """Indirect Prompt Injection via Tools."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent014 check logic
        return []
