"""DP020: Location Data Exposure.

Detects MCP tools that access or expose geographic location data. Location data can reveal home
addresses, workplace locations, travel patterns, and daily routines.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class LocationDataExposureCheck(BaseCheck):
    """Location Data Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp020 check logic
        return []
