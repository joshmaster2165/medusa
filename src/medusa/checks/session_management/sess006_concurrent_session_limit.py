"""SESS006: Missing Concurrent Session Limit.

Detects MCP server configurations that allow unlimited concurrent sessions for a single user or
identity. Without concurrent session limits, a compromised credential can be used to establish
multiple parallel sessions across different LLM clients without the legitimate user being aware.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ConcurrentSessionLimitCheck(BaseCheck):
    """Missing Concurrent Session Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sess006 check logic
        return []
