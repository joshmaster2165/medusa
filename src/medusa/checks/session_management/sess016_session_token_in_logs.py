"""SESS016: Session Token in Logs.

Detects MCP server configurations where session tokens or session identifiers are written to
application logs, access logs, or debug output. Logged session tokens can be harvested by anyone
with access to log files, log aggregation systems, or monitoring dashboards.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SessionTokenInLogsCheck(BaseCheck):
    """Session Token in Logs."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess016 check logic
        return []
