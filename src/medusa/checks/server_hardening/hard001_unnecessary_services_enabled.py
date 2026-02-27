"""HARD001: Unnecessary Services Enabled.

Detects MCP servers that expose capabilities, endpoints, or protocol features beyond what is
required for their intended function. Each unnecessary service increases the attack surface and
provides additional vectors for exploitation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnnecessaryServicesEnabledCheck(BaseCheck):
    """Unnecessary Services Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard001 check logic
        return []
