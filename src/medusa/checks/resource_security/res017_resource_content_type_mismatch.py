"""RES017: Resource Content-Type Mismatch.

Detects MCP resources that declare one content type in their metadata but serve content of a
different type. This mismatch can lead to client-side processing errors, security bypass through
type confusion, or exploitation of type-specific parsing vulnerabilities.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceContentTypeMismatchCheck(BaseCheck):
    """Resource Content-Type Mismatch."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res017 check logic
        return []
