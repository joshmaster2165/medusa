"""AUTH012: Missing Token Rotation.

Detects long-lived authentication tokens without a rotation mechanism. Tokens that persist for
extended periods without rotation increase the window of opportunity for attackers who have
obtained a compromised token.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingTokenRotationCheck(BaseCheck):
    """Missing Token Rotation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth012 check logic
        return []
