"""SESS008: Missing Session-IP Binding.

Detects MCP server sessions that are not bound to the originating client IP address or other
client fingerprint. Without session binding, a session token stolen from one network location
can be used from any other location to invoke tools and access resources on the MCP server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSessionBindingCheck(BaseCheck):
    """Missing Session-IP Binding."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess008 check logic
        return []
