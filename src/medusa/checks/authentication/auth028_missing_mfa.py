"""AUTH028: Missing Multi-Factor Authentication.

Detects MCP server configurations without support for multi-factor authentication. MFA provides
an additional layer of security beyond passwords, significantly reducing the risk of credential-
based attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingMfaCheck(BaseCheck):
    """Missing Multi-Factor Authentication."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth028 check logic
        return []
