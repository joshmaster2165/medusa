"""AUTH019: Token Scope Too Broad.

Detects authentication tokens with excessively broad permission scopes that grant access beyond
what is required for the token's intended use. Over-scoped tokens violate the principle of least
privilege and amplify the impact of token compromise.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class TokenScopeTooBroadCheck(BaseCheck):
    """Token Scope Too Broad."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth019 check logic
        return []
