"""INTG014: Missing Subresource Integrity.

Detects MCP servers that load remote resources (scripts, stylesheets, data files) without
Subresource Integrity (SRI) hashes. Without SRI, tampered remote resources are loaded without
detection.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SubresourceIntegrityMissingCheck(BaseCheck):
    """Missing Subresource Integrity."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement intg014 check logic
        return []
