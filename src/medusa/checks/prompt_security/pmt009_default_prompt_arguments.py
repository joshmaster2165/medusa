"""PMT009: Dangerous Default Prompt Arguments.

Detects MCP prompt definitions with default argument values that contain sensitive information,
overly permissive instructions, or dangerous operational parameters. Default values are used
when clients do not explicitly provide arguments, making them implicit and easy to overlook
during security review.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DefaultPromptArgumentsCheck(BaseCheck):
    """Dangerous Default Prompt Arguments."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement pmt009 check logic
        return []
