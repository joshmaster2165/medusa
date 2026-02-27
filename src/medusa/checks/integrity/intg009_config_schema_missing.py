"""INTG009: Missing Configuration Schema.

Checks whether the MCP server defines a schema for its configuration file. Without a schema,
invalid or malicious configuration values may be accepted without validation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ConfigSchemaMissingCheck(BaseCheck):
    """Missing Configuration Schema."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement intg009 check logic
        return []
