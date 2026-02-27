"""DOS011: Missing Recursive Operation Limit.

Detects MCP server tools that perform recursive operations without depth limits. Unbounded
recursion in file traversal, data processing, dependency resolution, or nested structure parsing
can exhaust stack space and cause server crashes.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class RecursiveOperationLimitCheck(BaseCheck):
    """Missing Recursive Operation Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dos011 check logic
        return []
