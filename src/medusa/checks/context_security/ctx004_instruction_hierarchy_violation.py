"""CTX004: Instruction Hierarchy Violation.

Detects MCP tool outputs that contain content attempting to override or contradict system-level
instructions. Tool content should never be able to elevate its privilege above the system
prompt.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InstructionHierarchyViolationCheck(BaseCheck):
    """Instruction Hierarchy Violation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ctx004 check logic
        return []
