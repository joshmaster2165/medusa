"""SHADOW004: Missing Server Metadata.

Detects MCP servers that lack descriptive metadata such as a human- readable description, author
information, contact details, or homepage URL. Missing metadata makes it difficult to verify
server legitimacy.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingServerMetadataCheck(BaseCheck):
    """Missing Server Metadata."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement shadow004 check logic
        return []
