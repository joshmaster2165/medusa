"""AGENT001: Missing Human-in-the-Loop.

Detects MCP server configurations where destructive or irreversible tool invocations can be
executed without requiring explicit user confirmation. Actions such as file deletion, database
modification, sending emails, or executing system commands should require a human approval step
before proceeding.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingHumanInLoopCheck(BaseCheck):
    """Missing Human-in-the-Loop."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent001 check logic
        return []
