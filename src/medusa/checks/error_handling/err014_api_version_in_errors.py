"""ERR014: API Version in Error Messages.

Detects MCP server error messages that include API version numbers, protocol version
identifiers, or internal build version strings. Version information helps attackers identify
specific software releases and their known vulnerabilities.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ApiVersionInErrorsCheck(BaseCheck):
    """API Version in Error Messages."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err014 check logic
        return []
