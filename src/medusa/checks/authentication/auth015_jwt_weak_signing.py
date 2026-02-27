"""AUTH015: JWT Weak Signing Key.

Detects JWT tokens signed with weak or short symmetric keys that are vulnerable to brute-force
or dictionary attacks. Short HMAC secrets can be cracked offline, allowing an attacker to forge
valid tokens.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class JwtWeakSigningCheck(BaseCheck):
    """JWT Weak Signing Key."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth015 check logic
        return []
