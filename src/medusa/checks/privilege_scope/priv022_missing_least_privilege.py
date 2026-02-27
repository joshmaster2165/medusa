"""PRIV022: Missing Least Privilege.

Detects MCP servers requesting more permissions than their tools require. Servers that request
broad filesystem, network, or system access when their tools only need narrow capabilities
violate the principle of least privilege.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingLeastPrivilegeCheck(BaseCheck):
    """Missing Least Privilege."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement priv022 check logic
        return []
