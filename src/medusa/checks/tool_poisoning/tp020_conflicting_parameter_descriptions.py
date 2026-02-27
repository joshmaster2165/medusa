"""TP020: Conflicting Parameter Descriptions.

Detects tool parameters whose descriptions contradict the stated purpose of the tool. For
example, a tool described as "read-only file viewer" with a parameter described as "path to
write output" indicates a mismatch that may signal deceptive intent.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ConflictingParameterDescriptionsCheck(BaseCheck):
    """Conflicting Parameter Descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp020 check logic
        return []
