"""HARD010: Exposed Version Information.

Detects MCP servers that expose version information in response headers, error messages,
capability declarations, or server metadata. Version information helps attackers identify
specific software releases and their known vulnerabilities.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ExposedVersionInformationCheck(BaseCheck):
    """Exposed Version Information."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard010 check logic
        return []
