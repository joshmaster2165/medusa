"""GOV005: Missing Incident Response Plan.

Detects MCP server deployments that lack a documented incident response plan for security
events. Without an incident response plan, organizations cannot effectively detect, contain,
eradicate, and recover from security incidents affecting MCP server operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingIncidentResponsePlanCheck(BaseCheck):
    """Missing Incident Response Plan."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        from medusa.checks.governance.gov001_missing_security_policy import _gov_check
        from medusa.utils.pattern_matching import INCIDENT_RESPONSE_KEYS

        meta = self.metadata()
        return _gov_check(
            snapshot,
            meta,
            config_keys=INCIDENT_RESPONSE_KEYS,
            missing_msg=(
                "Server '{server}' has no incident response configuration. "
                "Security incidents cannot be effectively contained or recovered from."
            ),
            present_msg="Server '{server}' has incident response configured.",
        )
