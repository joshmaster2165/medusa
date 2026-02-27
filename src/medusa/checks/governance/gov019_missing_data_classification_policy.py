"""GOV019: Missing Data Classification Policy.

Detects MCP server deployments that lack a data classification policy defining sensitivity
levels and handling requirements for data processed through tool invocations. Without
classification, all data receives the same handling regardless of sensitivity, leading to either
over-protection of low-sensitivity data or under-protection of high-sensitivity data.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingDataClassificationPolicyCheck(BaseCheck):
    """Missing Data Classification Policy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement gov019 check logic
        return []
