"""AUTH017: API Key in Insecure Headers.

Detects API keys transmitted in non-standard or commonly logged HTTP headers. Using headers like
X-Api-Key without TLS, or placing keys in headers that proxy servers and load balancers
routinely log, exposes credentials to interception.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ApiKeyInHeadersInsecureCheck(BaseCheck):
    """API Key in Insecure Headers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth017 check logic
        return []
