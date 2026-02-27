"""AUDIT008: Missing Access Logging.

Checks whether the MCP server logs resource access events. Without access logging, there is no
record of which resources were accessed, by whom, or when.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingAccessLoggingCheck(BaseCheck):
    """Missing Access Logging."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement audit008 check logic
        return []
