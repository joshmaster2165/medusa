"""PMT001: Prompt Argument Injection.

Detects MCP prompt templates that incorporate user-supplied arguments directly into prompt text
without sanitization or escaping. Malicious argument values can alter the prompt semantics,
inject new instructions, or override the intended prompt behavior.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class PromptArgumentInjectionCheck(BaseCheck):
    """Prompt Argument Injection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement pmt001 check logic
        return []
