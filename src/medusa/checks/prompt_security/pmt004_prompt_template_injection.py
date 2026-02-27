"""PMT004: Prompt Template Injection.

Detects MCP prompt templates where the template syntax itself can be exploited to inject
additional template directives. If the templating engine processes user input as template code
rather than literal text, attackers can execute arbitrary template operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PromptTemplateInjectionCheck(BaseCheck):
    """Prompt Template Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement pmt004 check logic
        return []
