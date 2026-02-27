"""TP019: Abnormal Description-to-Name Length Ratio.

Detects tools with suspiciously long descriptions relative to their tool name length. An
extremely high description-to-name ratio may indicate that the description contains hidden
instructions, encoded payloads, or excessive content designed to influence LLM behaviour beyond
documenting the tool's legitimate purpose.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ToolDescriptionLengthRatioCheck(BaseCheck):
    """Abnormal Description-to-Name Length Ratio."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp019 check logic
        return []
