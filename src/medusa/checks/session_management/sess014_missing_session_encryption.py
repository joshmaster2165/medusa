"""SESS014: Missing Session Encryption.

Detects MCP server sessions where session data is stored or transmitted without encryption.
Unencrypted session tokens and session state can be intercepted in transit or read from storage
by attackers with access to network traffic or the storage medium.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSessionEncryptionCheck(BaseCheck):
    """Missing Session Encryption."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess014 check logic
        return []
