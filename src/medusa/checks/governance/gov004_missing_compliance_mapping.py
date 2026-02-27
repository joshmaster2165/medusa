"""GOV004: Missing Compliance Mapping.

Detects MCP server deployments that lack a mapping between security controls and applicable
compliance frameworks such as SOC 2, ISO 27001, NIST CSF, or industry-specific regulations.
Compliance mapping demonstrates that security controls address regulatory requirements.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingComplianceMappingCheck(BaseCheck):
    """Missing Compliance Mapping."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        from medusa.checks.governance.gov001_missing_security_policy import _gov_check
        from medusa.utils.pattern_matching import COMPLIANCE_CONFIG_KEYS

        meta = self.metadata()
        return _gov_check(
            snapshot,
            meta,
            config_keys=COMPLIANCE_CONFIG_KEYS,
            missing_msg=(
                "Server '{server}' has no compliance mapping configuration. "
                "Security controls are not mapped to regulatory frameworks."
            ),
            present_msg="Server '{server}' has compliance mapping configured.",
        )
