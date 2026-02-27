"""AUDIT003: Insufficient Log Detail.

Detects MCP server logging configurations that lack essential detail such as caller identity,
tool invocation parameters, timestamps, or request correlation IDs. Incomplete logs hinder
security investigations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InsufficientLogDetailCheck(BaseCheck):
    """Insufficient Log Detail."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement audit003 check logic
        return []
