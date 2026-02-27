"""RES014: Missing Resource Schema Validation.

Detects MCP resources that lack schema definitions or validation for their content structure.
Without schema validation, resources can contain unexpected fields, malformed data, or
additional properties that may be processed in unintended ways by consumers.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceSchemaValidationCheck(BaseCheck):
    """Missing Resource Schema Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res014 check logic
        return []
