"""HARD013: Missing Request Validation.

Detects MCP servers that do not validate the structure, content type, and size of incoming
requests at the transport level before processing. Missing request validation allows malformed,
oversized, or incorrectly typed requests to reach application logic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingRequestValidationCheck(BaseCheck):
    """Missing Request Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard013 check logic
        return []
