"""TS014: WebSocket Without TLS.

Detects MCP server WebSocket connections using ws:// instead of wss://. Unencrypted WebSocket
connections expose all bidirectional communication to network-level interception, including tool
invocations, responses, and authentication tokens.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class WebsocketWithoutTlsCheck(BaseCheck):
    """WebSocket Without TLS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts014 check logic
        return []
