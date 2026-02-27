"""GOV010: Missing Third-Party Risk Assessment.

Detects MCP server deployments that integrate with external MCP servers, APIs, or services
without performing third-party risk assessments. External integrations introduce supply chain
risks including data exposure to third parties and dependency on their security posture.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingThirdPartyRiskCheck(BaseCheck):
    """Missing Third-Party Risk Assessment."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        from medusa.checks.governance.gov001_missing_security_policy import _gov_check
        from medusa.utils.pattern_matching import VENDOR_ASSESSMENT_KEYS

        meta = self.metadata()
        return _gov_check(
            snapshot,
            meta,
            config_keys=VENDOR_ASSESSMENT_KEYS,
            missing_msg=(
                "Server '{server}' has no third-party risk assessment configuration. "
                "External integrations introduce undocumented supply chain risks."
            ),
            present_msg="Server '{server}' has third-party risk assessment configured.",
        )
