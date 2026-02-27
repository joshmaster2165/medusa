"""HARD015: Missing Network Segmentation.

Detects MCP servers deployed without network segmentation between client-facing interfaces and
backend services. Without segmentation, a compromised MCP server has direct network access to
databases, internal APIs, and other sensitive backend services.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingNetworkSegmentationCheck(BaseCheck):
    """Missing Network Segmentation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard015 check logic
        return []
