"""GOV002: Missing Privacy Policy.

Detects MCP server deployments that lack a privacy policy defining how user data, conversation
content, tool inputs, and tool outputs are collected, processed, stored, and retained. MCP
servers often process sensitive personal information through LLM interactions and tool
invocations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.governance.gov001_missing_security_policy import _gov_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_PRIVACY_KEYS = {
    "privacy_policy",
    "privacy",
    "data_privacy",
    "gdpr",
    "ccpa",
    "data_protection_policy",
    "privacy_notice",
}


class MissingPrivacyPolicyCheck(BaseCheck):
    """Missing Privacy Policy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _gov_check(
            snapshot,
            meta,
            config_keys=_PRIVACY_KEYS,
            missing_msg=(
                "Server '{server}' has no privacy policy configuration. "
                "Data collection and processing practices are undocumented."
            ),
            present_msg="Server '{server}' has a privacy policy configured.",
        )
