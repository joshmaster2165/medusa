"""ERR004: Missing Error Handling.

Detects MCP tool implementations that lack error handling for operations that may fail, such as
file I/O, network requests, database queries, or external API calls. Unhandled errors cause
unpredictable behavior including crashes and data corruption.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingErrorHandlingCheck(BaseCheck):
    """Missing Error Handling."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err004 check logic
        return []
