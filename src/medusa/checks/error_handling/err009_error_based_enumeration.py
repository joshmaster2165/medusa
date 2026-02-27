"""ERR009: Error-Based Enumeration.

Detects MCP servers that return different error messages or codes for different failure
conditions in a way that allows attackers to enumerate valid resources, users, or tools. For
example, returning "tool not found" vs "access denied" reveals whether a tool exists.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ErrorBasedEnumerationCheck(BaseCheck):
    """Error-Based Enumeration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err009 check logic
        return []
