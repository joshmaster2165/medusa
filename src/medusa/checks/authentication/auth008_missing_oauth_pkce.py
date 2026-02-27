"""AUTH008: Missing OAuth PKCE.

Detects OAuth 2.0 authorization flows that do not implement Proof Key for Code Exchange (PKCE).
Without PKCE, authorization codes are vulnerable to interception attacks where a malicious
application captures the code and exchanges it for an access token.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingOauthPkceCheck(BaseCheck):
    """Missing OAuth PKCE."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth008 check logic
        return []
