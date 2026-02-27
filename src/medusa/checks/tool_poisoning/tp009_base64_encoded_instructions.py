"""TP009: Base64-Encoded Instructions in Descriptions.

Detects base64-encoded content embedded within tool descriptions. Attackers encode malicious
instructions in base64 to bypass content filtering and hide prompt injection payloads from human
reviewers. The LLM may decode and follow these hidden instructions during tool invocation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class Base64EncodedInstructionsCheck(BaseCheck):
    """Base64-Encoded Instructions in Descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp009 check logic
        return []
