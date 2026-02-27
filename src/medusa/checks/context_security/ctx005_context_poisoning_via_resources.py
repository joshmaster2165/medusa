"""CTX005: Context Poisoning via Resource Content.

Detects MCP resource content that contains adversarial text designed to manipulate LLM behavior.
Malicious resources can embed hidden instructions that the LLM follows when processing the
content.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ContextPoisoningViaResourcesCheck(BaseCheck):
    """Context Poisoning via Resource Content."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ctx005 check logic
        return []
