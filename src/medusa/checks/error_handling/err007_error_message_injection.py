"""ERR007: Error Message Injection.

Detects MCP server error messages that directly include unsanitized user input. When user-
supplied data is reflected in error responses without encoding or escaping, it creates injection
vectors that can manipulate LLM behavior or exploit downstream consumers.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ErrorMessageInjectionCheck(BaseCheck):
    """Error Message Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err007 check logic
        return []
