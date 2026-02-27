"""IV029: Unbounded Array Length.

Detects array-type tool parameters without maxItems constraints. Unbounded arrays allow
attackers to submit millions of items, causing memory exhaustion, excessive processing time, and
denial of service on the MCP server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ArrayLengthUnboundedCheck(BaseCheck):
    """Unbounded Array Length."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv029 check logic
        return []
