"""ERR001: Stack Trace Exposure.

Detects MCP server error responses that include full stack traces or exception tracebacks. Stack
traces often contain internal file paths, library versions, class names, and code logic that
help attackers understand the server internals and craft targeted exploits.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class StackTraceExposureCheck(BaseCheck):
    """Stack Trace Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err001 check logic
        return []
