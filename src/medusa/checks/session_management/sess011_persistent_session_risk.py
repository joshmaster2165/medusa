"""SESS011: Persistent Session Risk.

Detects MCP server configurations that support persistent or "remember me" sessions that survive
client restarts, browser closures, or system reboots. Persistent sessions extend the window of
exposure for session tokens stored on disk and can be exploited if the client device is
compromised.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PersistentSessionRiskCheck(BaseCheck):
    """Persistent Session Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess011 check logic
        return []
