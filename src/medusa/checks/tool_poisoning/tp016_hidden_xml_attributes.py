"""TP016: Hidden XML Attributes in Descriptions.

Detects XML attributes embedded in tool descriptions that smuggle hidden instructions to the
LLM. Attributes such as data-instruction, aria-label, or custom attributes within XML/HTML tags
can carry payloads that are processed by the LLM but not visible in rendered UI output.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class HiddenXmlAttributesCheck(BaseCheck):
    """Hidden XML Attributes in Descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp016 check logic
        return []
