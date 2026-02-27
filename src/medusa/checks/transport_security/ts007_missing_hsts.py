"""TS007: Missing HSTS Header.

Detects HTTP endpoints served without the Strict-Transport-Security (HSTS) header. Without HSTS,
browsers and clients may connect over HTTP before being redirected to HTTPS, creating a window
for man-in-the-middle attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingHstsCheck(BaseCheck):
    """Missing HSTS Header."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts007 check logic
        return []
