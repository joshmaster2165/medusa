"""HARD014: Insecure File Permissions.

Detects MCP server installations with overly permissive file permissions on configuration files,
credential stores, log files, and server binaries. World-readable or world-writable permissions
allow unauthorized access and modification of server components.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InsecureFilePermissionsCheck(BaseCheck):
    """Insecure File Permissions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard014 check logic
        return []
