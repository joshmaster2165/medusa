"""HARD002: Default Configuration in Production.

Detects MCP servers deployed with default configuration values that are intended for development
or testing. Default configurations typically use weak security settings, permissive access
controls, and debug-friendly options that are inappropriate for production.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DefaultConfigurationCheck(BaseCheck):
    """Default Configuration in Production."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard002 check logic
        return []
