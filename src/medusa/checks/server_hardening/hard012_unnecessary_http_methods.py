"""HARD012: Unnecessary HTTP Methods Enabled.

Detects MCP servers using HTTP-based transports that accept HTTP methods beyond those required
for MCP operation. Methods such as TRACE, OPTIONS, PUT, DELETE, and PATCH may be enabled by
default but are not needed for standard MCP communication.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnnecessaryHttpMethodsCheck(BaseCheck):
    """Unnecessary HTTP Methods Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard012 check logic
        return []
