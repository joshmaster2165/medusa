"""AUTH009: Bearer Token in URL Parameters.

Detects authentication tokens passed via URL query string parameters instead of HTTP headers.
Tokens in URLs are logged in server access logs, browser history, proxy logs, and referrer
headers, creating multiple exposure vectors.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class BearerTokenInUrlCheck(BaseCheck):
    """Bearer Token in URL Parameters."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth009 check logic
        return []
