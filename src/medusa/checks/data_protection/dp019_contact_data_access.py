"""DP019: Contact Data Access.

Detects MCP tools that access contacts, address books, or contact databases. Contact data
contains PII of third parties who have not consented to data processing.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ContactDataAccessCheck(BaseCheck):
    """Contact Data Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp019 check logic
        return []
