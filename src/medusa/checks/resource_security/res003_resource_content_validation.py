"""RES003: Missing Resource Content Validation.

Detects MCP resources that serve content without validating or sanitizing it before delivery to
clients. Unsanitized resource content may contain malicious payloads such as prompt injection
strings, script tags, or encoded attack sequences.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceContentValidationCheck(BaseCheck):
    """Missing Resource Content Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res003 check logic
        return []
