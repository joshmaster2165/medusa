"""TP011: Invisible Unicode Characters in Tool Descriptions.

Detects zero-width characters, bidirectional override markers, and other invisible Unicode
codepoints hidden within tool descriptions. These characters can conceal malicious instructions
that are invisible in UIs but processed by LLMs, enabling covert prompt injection.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class InvisibleUnicodeInDescriptionsCheck(BaseCheck):
    """Invisible Unicode Characters in Tool Descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp011 check logic
        return []
