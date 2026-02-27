"""SESS004: Session ID Stored in URL.

Detects MCP server configurations where session identifiers are transmitted or stored in URL
parameters rather than secure headers or cookies. Session IDs in URLs are exposed in browser
history, server logs, referrer headers, and proxy logs, making them trivially accessible to
attackers.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SessionStoredInUrlCheck(BaseCheck):
    """Session ID Stored in URL."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess004 check logic
        return []
