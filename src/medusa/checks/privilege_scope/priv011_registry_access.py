"""PRIV011: System Registry Access.

Detects MCP tools with access to system registry (Windows) or global configuration files (Linux
/etc/). System-level configuration access allows modifying OS behaviour, security settings, and
service configurations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class RegistryAccessCheck(BaseCheck):
    """System Registry Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement priv011 check logic
        return []
