"""GOV009: Missing Data Governance Framework.

Detects MCP server deployments that lack a data governance framework defining data ownership,
classification, handling requirements, and lifecycle management for data processed through tool
invocations and LLM interactions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingDataGovernanceCheck(BaseCheck):
    """Missing Data Governance Framework."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        from medusa.checks.governance.gov001_missing_security_policy import _gov_check
        from medusa.utils.pattern_matching import DATA_GOVERNANCE_KEYS

        meta = self.metadata()
        return _gov_check(
            snapshot,
            meta,
            config_keys=DATA_GOVERNANCE_KEYS,
            missing_msg=(
                "Server '{server}' has no data governance configuration. "
                "Data ownership, classification, and lifecycle are undocumented."
            ),
            present_msg="Server '{server}' has data governance framework configured.",
        )
