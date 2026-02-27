"""RES009: Missing Resource Size Limit.

Detects MCP resource handlers that do not enforce size limits on resource content, allowing
extremely large resources to be requested and processed. This can exhaust server memory, consume
excessive bandwidth, and overwhelm the LLM context window.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceSizeLimitCheck(BaseCheck):
    """Missing Resource Size Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res009 check logic
        return []
