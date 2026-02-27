"""AGENT016: Unauthorized External Communications.

Detects MCP configurations where agents can contact external services, APIs, or endpoints that
are not part of the approved communication set. Unauthorized external communications enable data
exfiltration, command-and- control channels, and interactions with malicious infrastructure.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnauthorizedExternalCommsCheck(BaseCheck):
    """Unauthorized External Communications."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent016 check logic
        return []
