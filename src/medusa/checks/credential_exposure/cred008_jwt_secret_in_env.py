"""CRED008: JWT Secret in Environment.

Detects JWT signing secrets stored in environment variables or configuration files. The JWT
secret is the root of trust for token verification; its exposure allows an attacker to forge
arbitrary valid tokens.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class JwtSecretInEnvCheck(BaseCheck):
    """JWT Secret in Environment."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred008 check logic
        return []
