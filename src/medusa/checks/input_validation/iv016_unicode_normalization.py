"""IV016: Unicode Normalization Bypass.

Detects input validation that can be bypassed via Unicode normalization transformations.
Characters that appear different in their composed and decomposed forms can bypass security
filters while being normalized to dangerous values by the processing system.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnicodeNormalizationCheck(BaseCheck):
    """Unicode Normalization Bypass."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv016 check logic
        return []
