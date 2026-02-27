"""SHADOW005: Suspicious Server Origin.

Detects MCP server binaries loaded from untrusted or unusual file system locations. Legitimate
servers should be installed in standard locations, not loaded from temporary directories,
downloads folders, or user-writable system paths.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SuspiciousServerOriginCheck(BaseCheck):
    """Suspicious Server Origin."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement shadow005 check logic
        return []
