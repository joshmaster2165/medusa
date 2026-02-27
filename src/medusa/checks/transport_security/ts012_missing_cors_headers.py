"""TS012: Missing CORS Headers.

Detects HTTP endpoints without Cross-Origin Resource Sharing (CORS) configuration. Missing CORS
headers can either block legitimate cross-origin requests or indicate that no cross-origin
access policy has been considered, potentially defaulting to an insecure state.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingCorsHeadersCheck(BaseCheck):
    """Missing CORS Headers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts012 check logic
        return []
