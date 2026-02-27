"""INTG016: Insecure Config File Permissions.

Detects MCP server configuration files with overly permissive file system permissions. World-
readable or group-writable configuration files expose secrets and allow unauthorised
modification.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ConfigFilePermissionsCheck(BaseCheck):
    """Insecure Config File Permissions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement intg016 check logic
        return []
