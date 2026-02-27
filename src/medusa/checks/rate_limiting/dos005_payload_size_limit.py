"""DOS005: Missing Payload Size Limit.

Detects MCP server configurations that do not enforce size limits on request and response
payloads. Without size limits, attackers can send oversized requests that consume memory during
parsing or trigger tools to generate massive responses that exhaust server resources.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PayloadSizeLimitCheck(BaseCheck):
    """Missing Payload Size Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dos005 check logic
        return []
