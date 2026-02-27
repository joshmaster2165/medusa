"""HARD004: Directory Listing Enabled.

Detects MCP servers with file-based resource handlers that enable directory listing, allowing
clients to enumerate all files and subdirectories within served paths. Directory listings reveal
the server file structure and expose files that may not be intended for access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DirectoryListingEnabledCheck(BaseCheck):
    """Directory Listing Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard004 check logic
        return []
