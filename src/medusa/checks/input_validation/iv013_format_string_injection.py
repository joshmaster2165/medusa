"""IV013: Format String Injection.

Detects tool parameters used in string formatting operations without sanitization. Parameters
passed to printf-style, f-string, or template string formatters can inject format specifiers
that read memory, cause crashes, or write to arbitrary memory locations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class FormatStringInjectionCheck(BaseCheck):
    """Format String Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv013 check logic
        return []
