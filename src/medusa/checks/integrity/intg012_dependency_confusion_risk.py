"""INTG012: Dependency Confusion Risk.

Detects private package names that may be vulnerable to dependency confusion attacks where a
public package with the same name is installed instead of the intended private package.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DependencyConfusionRiskCheck(BaseCheck):
    """Dependency Confusion Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement intg012 check logic
        return []
