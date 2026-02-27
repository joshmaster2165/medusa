"""TS005: Mixed Content Transport.

Detects MCP servers that mix HTTP and HTTPS connections in their transport configuration. Mixed
content downgrades the security of the entire communication channel, as any unencrypted
connection can be intercepted to steal credentials or modify traffic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MixedContentCheck(BaseCheck):
    """Mixed Content Transport."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts005 check logic
        return []
