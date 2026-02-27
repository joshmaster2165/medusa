"""AUTH014: JWT Algorithm None Attack.

Detects JWT tokens that accept the 'none' algorithm, which disables signature verification
entirely. An attacker can forge arbitrary JWT tokens by setting the algorithm to 'none' and
removing the signature, granting themselves any identity or permission claims.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class JwtAlgorithmNoneCheck(BaseCheck):
    """JWT Algorithm None Attack."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth014 check logic
        return []
