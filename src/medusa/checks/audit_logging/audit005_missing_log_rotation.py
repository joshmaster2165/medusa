"""AUDIT005: Missing Log Rotation.

Checks whether the MCP server has a log rotation policy configured. Without log rotation, log
files grow unbounded, eventually exhausting disk space and causing service disruption.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingLogRotationCheck(BaseCheck):
    """Missing Log Rotation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement audit005 check logic
        return []
