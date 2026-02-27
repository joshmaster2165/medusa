"""IV026: Wildcard Parameter Matching.

Detects tool parameters that accept wildcard patterns (*, ?, **) without restrictions.
Unrestricted glob or wildcard parameters can match unintended files, directories, or resources,
expanding the operation scope beyond user intent.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class WildcardParameterCheck(BaseCheck):
    """Wildcard Parameter Matching."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv026 check logic
        return []
