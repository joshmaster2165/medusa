"""SM013: Default Secrets in Use.

Detects MCP servers that are using default secrets, example tokens, or placeholder credentials
that were included in documentation, sample configurations, or initial setup scripts. Default
secrets are publicly known and provide trivial unauthorized access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DefaultSecretsInUseCheck(BaseCheck):
    """Default Secrets in Use."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sm013 check logic
        return []
