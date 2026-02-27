"""HARD008: Insecure Default Credentials.

Detects MCP servers that ship with default usernames, passwords, API keys, or tokens that are
documented, predictable, or shared across all installations. Default credentials are the most
common entry point for server compromise.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InsecureDefaultCredentialsCheck(BaseCheck):
    """Insecure Default Credentials."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard008 check logic
        return []
