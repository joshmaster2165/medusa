"""PMT010: Prompt Output Manipulation.

Detects MCP prompt definitions that can be manipulated to control or redirect the LLM output
format, destination, or content in ways unintended by the prompt designer. Output manipulation
enables data exfiltration, instruction injection into downstream systems, and evasion of output
filters.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PromptOutputManipulationCheck(BaseCheck):
    """Prompt Output Manipulation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement pmt010 check logic
        return []
