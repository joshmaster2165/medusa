"""GOV003: Missing Terms of Service.

Detects MCP server deployments that lack terms of service defining acceptable use, limitations
of liability, and user responsibilities. Terms of service establish the contractual framework
for MCP server usage and set expectations for both operators and users.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingTermsOfServiceCheck(BaseCheck):
    """Missing Terms of Service."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement gov003 check logic
        return []
