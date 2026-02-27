"""SHADOW003: Duplicate Tool Names Across Servers.

Detects multiple MCP servers in the same client configuration that expose tools with identical
names. Duplicate tool names create ambiguity about which server handles a given tool invocation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DuplicateToolNamesAcrossServersCheck(BaseCheck):
    """Duplicate Tool Names Across Servers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement shadow003 check logic
        return []
