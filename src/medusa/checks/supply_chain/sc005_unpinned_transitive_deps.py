"""SC005: Unpinned Transitive Dependencies.

Detects MCP server dependency configurations where transitive dependencies are not version-
constrained. Unpinned transitive dependencies can silently update to malicious versions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnpinnedTransitiveDepsCheck(BaseCheck):
    """Unpinned Transitive Dependencies."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sc005 check logic
        return []
