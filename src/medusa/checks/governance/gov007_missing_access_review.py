"""GOV007: Missing Access Review Process.

Detects MCP server deployments that lack periodic access reviews to verify that user
permissions, tool access grants, and API keys remain appropriate. Without access reviews,
permissions accumulate over time and former users may retain access they no longer need.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingAccessReviewCheck(BaseCheck):
    """Missing Access Review Process."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement gov007 check logic
        return []
