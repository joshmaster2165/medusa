"""IV019: Missing Input Length Constraint.

Detects string parameters in tool schemas without maxLength constraints. Unbounded string
parameters allow attackers to submit extremely large inputs that cause memory exhaustion, buffer
overflows, or denial of service through excessive processing.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingLengthConstraintCheck(BaseCheck):
    """Missing Input Length Constraint."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv019 check logic
        return []
