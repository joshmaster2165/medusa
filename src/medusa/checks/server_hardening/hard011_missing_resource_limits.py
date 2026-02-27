"""HARD011: Missing Server Resource Limits.

Detects MCP servers that do not enforce limits on system resource consumption including memory
usage, CPU time, file descriptor count, disk space, and network connections. Without resource
limits, a single request can consume all available server resources.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingResourceLimitsCheck(BaseCheck):
    """Missing Server Resource Limits."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard011 check logic
        return []
