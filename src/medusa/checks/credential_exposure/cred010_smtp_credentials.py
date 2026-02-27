"""CRED010: SMTP Credential Exposure.

Detects email server credentials (SMTP username, password, API keys) in MCP server
configuration. SMTP credentials allow sending emails as the configured sender, enabling phishing
and spam campaigns through the organization's mail infrastructure.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SmtpCredentialsCheck(BaseCheck):
    """SMTP Credential Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred010 check logic
        return []
