"""ERR006: Missing Error Codes.

Detects MCP server error responses that lack standardized error codes, relying solely on free-
text error messages. Without consistent error codes, clients cannot programmatically handle
different error conditions or implement proper retry logic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingErrorCodesCheck(BaseCheck):
    """Missing Error Codes."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err006 check logic
        return []
