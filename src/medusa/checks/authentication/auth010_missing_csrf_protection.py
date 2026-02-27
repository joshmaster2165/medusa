"""AUTH010: Missing CSRF Protection.

Detects HTTP transport endpoints without Cross-Site Request Forgery protection. MCP servers
exposed over HTTP without CSRF tokens or same-origin validation are vulnerable to attacks where
a malicious website forces the user's browser to invoke MCP tools.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingCsrfProtectionCheck(BaseCheck):
    """Missing CSRF Protection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth010 check logic
        return []
