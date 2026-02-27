"""AUDIT006: Missing Security Alerting.

Checks whether the MCP server has alerting configured for security- relevant events. Without
alerting, security incidents are only discovered during manual log review, which may be too
late.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingAlertingCheck(BaseCheck):
    """Missing Security Alerting."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement audit006 check logic
        return []
