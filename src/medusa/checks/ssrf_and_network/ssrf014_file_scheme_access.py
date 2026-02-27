"""SSRF014: File Scheme URL Access.

Detects MCP server tools that accept file:// URLs, enabling direct access to the local
filesystem of the MCP server. File scheme URLs can read configuration files, credentials,
private keys, and other sensitive data stored on the server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class FileSchemeAccessCheck(BaseCheck):
    """File Scheme URL Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf014 check logic
        return []
