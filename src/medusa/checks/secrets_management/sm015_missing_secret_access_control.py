"""SM015: Missing Secret Access Control.

Detects MCP servers where secrets are accessible to all server components, tools, and processes
without granular access controls. Missing access control on secrets means that any tool or code
running within the server can access all secrets regardless of whether it needs them.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSecretAccessControlCheck(BaseCheck):
    """Missing Secret Access Control."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sm015 check logic
        return []
