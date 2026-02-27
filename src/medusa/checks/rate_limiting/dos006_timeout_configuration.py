"""DOS006: Missing Timeout Configuration.

Detects MCP server tools that execute without configured timeouts. Missing timeouts allow tool
invocations to run indefinitely, consuming server resources and blocking processing capacity for
other requests. Long-running tools can be intentionally triggered as a denial-of-service
technique.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class TimeoutConfigurationCheck(BaseCheck):
    """Missing Timeout Configuration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dos006 check logic
        return []
