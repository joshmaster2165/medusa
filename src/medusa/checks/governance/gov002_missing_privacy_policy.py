"""GOV002: Missing Privacy Policy.

Detects MCP server deployments that lack a privacy policy defining how user data, conversation
content, tool inputs, and tool outputs are collected, processed, stored, and retained. MCP
servers often process sensitive personal information through LLM interactions and tool
invocations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingPrivacyPolicyCheck(BaseCheck):
    """Missing Privacy Policy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement gov002 check logic
        return []
