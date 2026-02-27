"""TP017: Markdown Link Injection in Descriptions.

Detects hidden markdown links in tool descriptions that can trigger data exfiltration. Markdown
image tags and links with encoded parameters can cause the LLM to request external URLs, leaking
context data via query strings or path segments.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MarkdownInjectionCheck(BaseCheck):
    """Markdown Link Injection in Descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp017 check logic
        return []
