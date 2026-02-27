"""SESS013: Overly Broad Session Cookie Scope.

Detects MCP servers that set session cookies with overly broad domain or path scopes. Cookies
scoped to parent domains or root paths are sent with requests to all subdomains and paths,
exposing session tokens to unrelated services and increasing the risk of token capture.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SessionCookieScopeCheck(BaseCheck):
    """Overly Broad Session Cookie Scope."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess013 check logic
        return []
