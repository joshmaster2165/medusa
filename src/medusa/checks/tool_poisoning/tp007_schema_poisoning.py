"""TP007: Schema Poisoning via Default Values.

Detects tool schemas containing default parameter values that inject unintended instructions or
override user-supplied intent. Attackers embed malicious defaults in JSON Schema definitions so
that when the LLM omits a parameter, the default silently takes effect with harmful
consequences.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SchemaPoisoningCheck(BaseCheck):
    """Schema Poisoning via Default Values."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp007 check logic
        return []
