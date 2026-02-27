"""ERR008: Unhandled Exception Risk.

Detects MCP server implementations that lack a top-level catch-all exception handler at the
transport boundary. Without a global exception handler, unexpected errors can crash the server
process or leak raw exception details to clients.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnhandledExceptionRiskCheck(BaseCheck):
    """Unhandled Exception Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err008 check logic
        return []
