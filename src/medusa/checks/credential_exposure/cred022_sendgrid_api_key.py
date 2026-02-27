"""CRED022: SendGrid API Key Exposure.

Detects SendGrid API keys in MCP server configuration or environment. SendGrid API keys grant
permissions to send emails, manage contacts, and access email analytics through the SendGrid
platform.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SendgridApiKeyCheck(BaseCheck):
    """SendGrid API Key Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred022 check logic
        return []
