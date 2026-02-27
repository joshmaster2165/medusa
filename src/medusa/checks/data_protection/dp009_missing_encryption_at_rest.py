"""DP009: Missing Encryption at Rest.

Detects MCP server configurations where stored data, caches, or persistent state lack encryption
at rest. Unencrypted data on disk is vulnerable to theft if the host is compromised.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingEncryptionAtRestCheck(BaseCheck):
    """Missing Encryption at Rest."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp009 check logic
        return []
