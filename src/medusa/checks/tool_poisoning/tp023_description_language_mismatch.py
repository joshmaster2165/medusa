"""TP023: Description Language Mismatch.

Detects tool descriptions written in a different natural language than the server's configured
locale or the majority of other tool descriptions. Language mismatches can indicate copied
content from foreign attack toolkits or deliberate obfuscation of malicious instructions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DescriptionLanguageMismatchCheck(BaseCheck):
    """Description Language Mismatch."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp023 check logic
        return []
