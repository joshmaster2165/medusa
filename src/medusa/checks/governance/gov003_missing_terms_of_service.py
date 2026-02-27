"""GOV003: Missing Terms of Service.

Detects MCP server deployments that lack terms of service defining acceptable use, limitations
of liability, and user responsibilities. Terms of service establish the contractual framework
for MCP server usage and set expectations for both operators and users.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.governance.gov001_missing_security_policy import _gov_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_TOS_KEYS = {"terms_of_service", "terms", "tos", "acceptable_use", "usage_policy", "terms_url"}


class MissingTermsOfServiceCheck(BaseCheck):
    """Missing Terms of Service."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _gov_check(
            snapshot,
            meta,
            config_keys=_TOS_KEYS,
            missing_msg=(
                "Server '{server}' has no terms of service configuration. "
                "Acceptable use expectations are undocumented."
            ),
            present_msg="Server '{server}' has terms of service configured.",
        )
