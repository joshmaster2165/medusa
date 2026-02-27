"""AUTH022: Missing Token Revocation.

Detects MCP server configurations without a mechanism to revoke compromised or unused tokens.
Without revocation, compromised tokens remain valid until they expire, which may be a long time
or never.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingTokenRevocationCheck(BaseCheck):
    """Missing Token Revocation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth022 check logic
        return []
