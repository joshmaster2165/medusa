"""HARD007: Missing Server-Level Input Sanitization.

Detects MCP servers that lack a centralized input sanitization layer at the server transport
boundary. Without server-level sanitization, each tool and resource handler must independently
implement input validation, leading to inconsistent protection across the server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingInputSanitizationCheck(BaseCheck):
    """Missing Server-Level Input Sanitization."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement hard007 check logic
        return []
