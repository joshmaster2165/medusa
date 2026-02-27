"""DP027: Child Data Protection (COPPA).

Detects MCP tools that may process children's data without implementing COPPA-required
protections. Tools accessible to children or processing data about minors must comply with
enhanced privacy requirements.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ChildDataProtectionCheck(BaseCheck):
    """Child Data Protection (COPPA)."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp027 check logic
        return []
