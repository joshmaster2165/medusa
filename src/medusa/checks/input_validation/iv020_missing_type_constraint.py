"""IV020: Missing Type Constraint.

Detects tool parameters without explicit type definitions in their JSON Schema. Parameters
lacking a type constraint accept any JSON value, making it impossible to validate input
structure and enabling type confusion attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingTypeConstraintCheck(BaseCheck):
    """Missing Type Constraint."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv020 check logic
        return []
