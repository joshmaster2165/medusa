"""SM010: Missing Secret Encryption at Rest.

Detects MCP servers that store secrets without encrypting them at rest. Unencrypted secret
storage means that physical access to the storage medium, database dumps, or backup files
directly exposes all stored secrets in plaintext.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSecretEncryptionCheck(BaseCheck):
    """Missing Secret Encryption at Rest."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sm010 check logic
        return []
