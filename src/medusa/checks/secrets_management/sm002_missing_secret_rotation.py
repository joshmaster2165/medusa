"""SM002: Missing Secret Rotation.

Detects MCP servers that use long-lived secrets without a rotation policy or mechanism. Secrets
that are never rotated remain valid indefinitely, extending the window of opportunity for
compromised credentials to be exploited.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSecretRotationCheck(BaseCheck):
    """Missing Secret Rotation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sm002 check logic
        return []
