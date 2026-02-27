"""DP028: Missing Data Portability.

Checks whether the MCP server provides a mechanism for users to export their data in a portable
format. Data portability is a right under GDPR and similar regulations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DataPortabilityMissingCheck(BaseCheck):
    """Missing Data Portability."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp028 check logic
        return []
