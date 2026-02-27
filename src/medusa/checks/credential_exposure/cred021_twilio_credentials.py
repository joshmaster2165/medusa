"""CRED021: Twilio Credential Exposure.

Detects Twilio account SID and auth tokens in MCP server configuration. Twilio credentials grant
access to send SMS messages, make phone calls, and access communication logs through the Twilio
API.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class TwilioCredentialsCheck(BaseCheck):
    """Twilio Credential Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred021 check logic
        return []
