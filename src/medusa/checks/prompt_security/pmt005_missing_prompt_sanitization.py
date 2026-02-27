"""PMT005: Missing Prompt Sanitization.

Detects MCP prompt handlers that pass prompt content and arguments to the LLM without any
sanitization, filtering, or validation. Missing sanitization allows any content in prompts and
arguments to reach the LLM unmodified, including injection payloads.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingPromptSanitizationCheck(BaseCheck):
    """Missing Prompt Sanitization."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement pmt005 check logic
        return []
