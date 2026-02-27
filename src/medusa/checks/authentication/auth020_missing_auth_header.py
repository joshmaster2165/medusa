"""AUTH020: Missing Authorization Header.

Detects MCP servers using HTTP transport without any Authorization header configuration. Servers
that do not expect or validate Authorization headers accept all requests as authenticated,
providing no access control.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingAuthHeaderCheck(BaseCheck):
    """Missing Authorization Header."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth020 check logic
        return []
