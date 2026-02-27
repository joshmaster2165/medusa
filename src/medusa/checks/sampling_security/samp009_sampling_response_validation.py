"""SAMP009: Missing Sampling Response Validation.

Detects MCP server implementations that process sampling responses from the LLM without
validation. Unvalidated sampling responses may contain unexpected content, malformed data, or
injected instructions that the server processes as trusted input, leading to secondary injection
attacks or logic errors.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SamplingResponseValidationCheck(BaseCheck):
    """Missing Sampling Response Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp009 check logic
        return []
