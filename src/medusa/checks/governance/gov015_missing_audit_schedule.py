"""GOV015: Missing Audit Schedule.

Detects MCP server deployments that lack a defined schedule for security audits and assessments.
Without regular audits, security controls degrade over time, new vulnerabilities go undetected,
and compliance drift occurs without correction.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingAuditScheduleCheck(BaseCheck):
    """Missing Audit Schedule."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        from medusa.checks.governance.gov001_missing_security_policy import _gov_check
        from medusa.utils.pattern_matching import GOVERNANCE_AUDIT_KEYS

        meta = self.metadata()
        return _gov_check(
            snapshot,
            meta,
            config_keys=GOVERNANCE_AUDIT_KEYS,
            missing_msg=(
                "Server '{server}' has no audit schedule configuration. "
                "Security controls degrade without periodic assessments."
            ),
            present_msg="Server '{server}' has an audit schedule configured.",
        )
