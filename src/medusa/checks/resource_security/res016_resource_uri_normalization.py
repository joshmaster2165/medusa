"""RES016: Missing URI Normalization.

Detects MCP resource handlers that do not normalize URIs before processing, allowing different
URI representations to bypass access controls. URL encoding, case variations, path folding, and
trailing slashes can create equivalent URIs that receive different access control decisions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceUriNormalizationCheck(BaseCheck):
    """Missing URI Normalization."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res016 check logic
        return []
