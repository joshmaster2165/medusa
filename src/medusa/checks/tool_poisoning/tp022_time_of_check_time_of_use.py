"""TP022: TOCTOU in Tool Definitions.

Detects time-of-check-time-of-use vulnerabilities where tool definitions can change between the
listing phase (when tools are reviewed) and the invocation phase (when tools are executed). A
malicious server can present safe definitions during listing but swap them at invocation time.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class TimeOfCheckTimeOfUseCheck(BaseCheck):
    """TOCTOU in Tool Definitions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp022 check logic
        return []
