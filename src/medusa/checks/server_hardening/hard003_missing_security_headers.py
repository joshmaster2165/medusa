"""HARD003: Missing Security Headers.

Detects MCP servers using HTTP-based transports that do not set security-relevant response
headers such as Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security,
X-Frame-Options, and Cache-Control for sensitive responses.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingSecurityHeadersCheck(BaseCheck):
    """Missing Security Headers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard003 check logic
        return []
