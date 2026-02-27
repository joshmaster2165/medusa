"""AUTH006: Missing Token Expiration.

Detects JWT tokens and API keys without expiration claims or time-to-live settings. Tokens that
never expire remain valid indefinitely, even after the user's access should have been revoked or
the token has been compromised.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingTokenExpiryCheck(BaseCheck):
    """Missing Token Expiration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth006 check logic
        return []
