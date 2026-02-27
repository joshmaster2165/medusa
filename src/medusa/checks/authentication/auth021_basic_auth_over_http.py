"""AUTH021: Basic Auth Over HTTP.

Detects HTTP Basic authentication used over unencrypted HTTP connections. Basic auth transmits
credentials as base64-encoded plaintext, which is trivially decoded by any network observer when
TLS is not used.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class BasicAuthOverHttpCheck(BaseCheck):
    """Basic Auth Over HTTP."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth021 check logic
        return []
