"""IV035: HTML Injection Risk.

Detects tool parameters whose output may be rendered in HTML contexts without proper escaping.
Parameters containing HTML tags or entities can inject content into web pages, enabling cross-
site scripting and content spoofing attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class HtmlInjectionCheck(BaseCheck):
    """HTML Injection Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement iv035 check logic
        return []
