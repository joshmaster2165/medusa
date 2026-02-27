"""TP012: URL Injection in Tool Descriptions.

Detects suspicious URLs embedded in tool descriptions that may be used for data exfiltration or
phishing. Tool descriptions containing URLs to external services can direct the LLM to send
sensitive data to attacker-controlled endpoints during tool invocation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ToolDescriptionUrlInjectionCheck(BaseCheck):
    """URL Injection in Tool Descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp012 check logic
        return []
