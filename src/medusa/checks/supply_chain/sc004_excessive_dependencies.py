"""SC004: Excessive Dependency Count.

Detects MCP servers with an excessive number of transitive dependencies. Each additional
dependency increases the attack surface and the likelihood of including a compromised package.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ExcessiveDependenciesCheck(BaseCheck):
    """Excessive Dependency Count."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sc004 check logic
        return []
