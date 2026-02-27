"""SSRF018: Internal API Exposure.

Detects MCP server tools that can access internal API endpoints intended only for service-to-
service communication. Internal APIs typically lack authentication and authorization controls
because they are assumed to be unreachable from external sources.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InternalApiExposureCheck(BaseCheck):
    """Internal API Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf018 check logic
        return []
