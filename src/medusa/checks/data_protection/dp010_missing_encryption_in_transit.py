"""DP010: Missing Encryption in Transit.

Detects MCP server connections that transmit data without encryption. Unencrypted transport
channels expose data to interception via man-in-the-middle attacks on the network.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingEncryptionInTransitCheck(BaseCheck):
    """Missing Encryption in Transit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp010 check logic
        return []
