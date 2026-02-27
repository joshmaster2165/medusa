"""PRIV004: Cloud Metadata Service Access.

Detects MCP tools that can access cloud instance metadata endpoints (e.g.
http://169.254.169.254). Cloud metadata services expose instance credentials, network
configuration, and user data without authentication, making them high-value SSRF targets.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class CloudMetadataAccessCheck(BaseCheck):
    """Cloud Metadata Service Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement priv004 check logic
        return []
