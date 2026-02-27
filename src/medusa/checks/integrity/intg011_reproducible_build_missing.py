"""INTG011: Missing Reproducible Build.

Checks whether the MCP server can be built reproducibly from source. Without reproducible
builds, there is no way to verify that the distributed binary matches the published source code.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ReproducibleBuildMissingCheck(BaseCheck):
    """Missing Reproducible Build."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement intg011 check logic
        return []
