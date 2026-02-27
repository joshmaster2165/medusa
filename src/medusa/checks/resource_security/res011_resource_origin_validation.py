"""RES011: Missing Resource Origin Validation.

Detects MCP resources that fetch or proxy content from external origins without validating the
source. Resources that pull data from user-specified URLs, external APIs, or remote file systems
without origin validation enable SSRF and data poisoning attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceOriginValidationCheck(BaseCheck):
    """Missing Resource Origin Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res011 check logic
        return []
