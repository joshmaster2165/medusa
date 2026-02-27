"""DP017: Keylogger Risk.

Detects MCP tools with keystroke capture capabilities. Keylogging is one of the most invasive
forms of surveillance and can capture passwords, private communications, and all user input.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class KeyloggerRiskCheck(BaseCheck):
    """Keylogger Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp017 check logic
        return []
