"""DP006: Unmasked Sensitive Fields.

Detects MCP tool outputs and resource contents that return PII or secrets (e.g. full SSNs,
credit card numbers, API keys) without masking or redaction. Sensitive fields should be
partially or fully masked before being sent to LLM clients.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnmaskedSensitiveFieldsCheck(BaseCheck):
    """Unmasked Sensitive Fields."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp006 check logic
        return []
