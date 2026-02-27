"""HARD006: Debug Endpoints Enabled.

Detects MCP servers that expose debug or diagnostic endpoints in production deployments. Debug
endpoints may include health checks with internal details, profiling endpoints, memory dumps, or
configuration inspection endpoints that reveal sensitive internals.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DebugEndpointsEnabledCheck(BaseCheck):
    """Debug Endpoints Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard006 check logic
        return []
