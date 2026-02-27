"""IV017: Null Byte Injection Risk.

Detects tool parameters that may be vulnerable to null byte injection. Null bytes (\\x00) in
file paths or strings can truncate processing in C-based libraries, causing the application to
operate on a different resource than validated.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class NullByteInjectionCheck(BaseCheck):
    """Null Byte Injection Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv017 check logic
        return []
