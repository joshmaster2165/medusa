"""TP021: Tool Capability Escalation.

Detects tools that request or imply capabilities beyond their stated purpose. For example, a
tool described as a "text formatter" that accepts file path parameters or network URLs indicates
capability escalation beyond its documented scope.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ToolCapabilityEscalationCheck(BaseCheck):
    """Tool Capability Escalation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp021 check logic
        return []
