"""AUTH016: Missing Authentication on Sensitive Tools.

Detects MCP tools that perform sensitive operations (file access, database queries, network
requests, system commands) without requiring authentication. Unauthenticated access to dangerous
tools allows any client to perform privileged operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingAuthOnToolsCheck(BaseCheck):
    """Missing Authentication on Sensitive Tools."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth016 check logic
        return []
