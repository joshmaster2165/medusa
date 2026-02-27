"""GOV020: Missing Vendor Security Assessment.

Detects MCP server deployments that use third-party MCP servers, tools, or LLM providers without
conducting vendor security assessments. Third-party vendors that process data through MCP
integrations must meet security requirements commensurate with the sensitivity of the data they
handle.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingVendorAssessmentCheck(BaseCheck):
    """Missing Vendor Security Assessment."""

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
                "Server '{server}' has no vendor security assessment configuration. "
                "Third-party LLM providers or tools may not meet security requirements."
            ),
            present_msg="Server '{server}' has vendor security assessment configured.",
        )
