"""DP029: Missing Right to Deletion.

Checks whether the MCP server provides a mechanism for users to request deletion of their
personal data. The right to erasure is a fundamental requirement under GDPR and CCPA.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class RightToDeletionMissingCheck(BaseCheck):
    """Missing Right to Deletion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp029 check logic
        return []
