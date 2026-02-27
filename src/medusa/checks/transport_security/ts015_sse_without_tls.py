"""TS015: SSE Without TLS.

Detects Server-Sent Events (SSE) connections over unencrypted HTTP. MCP servers using SSE
transport over HTTP expose the event stream to network interception, including tool results,
notifications, and potentially sensitive server-pushed data.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SseWithoutTlsCheck(BaseCheck):
    """SSE Without TLS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts015 check logic
        return []
