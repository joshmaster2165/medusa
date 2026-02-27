"""DP024: Biometric Data Handling.

Detects MCP tools that process biometric data such as fingerprints, facial features, voice
prints, or iris scans. Biometric data is immutable and cannot be changed if compromised.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class BiometricDataHandlingCheck(BaseCheck):
    """Biometric Data Handling."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp024 check logic
        return []
