"""SSRF005: Localhost Access.

Detects MCP server tools that allow requests to localhost addresses including 127.0.0.1, ::1,
and the localhost hostname. Localhost access from MCP tools enables exploitation of services
running on the same host as the MCP server, including databases, admin interfaces, and debugging
endpoints.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class LocalhostAccessCheck(BaseCheck):
    """Localhost Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf005 check logic
        return []
