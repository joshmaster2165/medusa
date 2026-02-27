"""TP010: Cross-Server Tool Name Collision.

Detects when multiple MCP servers expose tools with identical names. When two servers register a
tool with the same name, the LLM may invoke the wrong implementation, allowing a malicious
server to shadow a legitimate tool and intercept its invocations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class CrossServerToolShadowingCheck(BaseCheck):
    """Cross-Server Tool Name Collision."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp010 check logic
        return []
