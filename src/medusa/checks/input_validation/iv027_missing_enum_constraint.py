"""IV027: Missing Enum Constraint on Action Parameters.

Detects action, operation, or type parameters that accept free-form strings instead of being
restricted to an enumerated set of valid values. Parameters that determine the tool's behaviour
mode should use enum constraints to prevent unexpected operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingEnumConstraintCheck(BaseCheck):
    """Missing Enum Constraint on Action Parameters."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv027 check logic
        return []
