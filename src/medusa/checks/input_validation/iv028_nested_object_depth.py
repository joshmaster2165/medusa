"""IV028: Excessive Nested Object Depth.

Detects tool parameters that allow deeply nested object structures without depth limits.
Excessive nesting can hide malicious payloads deep in the structure, evade validation, and cause
stack overflow or excessive memory consumption during parsing.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class NestedObjectDepthCheck(BaseCheck):
    """Excessive Nested Object Depth."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv028 check logic
        return []
