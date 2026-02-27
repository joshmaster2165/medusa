"""SM001: Plaintext Secrets in Configuration.

Detects MCP server configuration files that contain secrets such as API keys, database
passwords, encryption keys, and OAuth tokens stored in plaintext without encryption. Plaintext
secrets in configuration files are the most common credential exposure vector.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PlaintextSecretsInConfigCheck(BaseCheck):
    """Plaintext Secrets in Configuration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sm001 check logic
        return []
