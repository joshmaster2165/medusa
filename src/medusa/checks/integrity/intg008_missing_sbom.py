"""INTG008: Missing Software Bill of Materials.

Checks whether the MCP server provides a Software Bill of Materials (SBOM). An SBOM lists all
components and dependencies, enabling supply chain transparency and vulnerability tracking.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSbomCheck(BaseCheck):
    """Missing Software Bill of Materials."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement intg008 check logic
        return []
