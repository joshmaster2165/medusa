"""TP025: Tool Annotation Abuse.

Detects misuse of MCP tool annotations such as readOnlyHint, destructiveHint, idempotentHint,
and openWorldHint. A malicious server can set readOnlyHint to true on a destructive tool or
destructiveHint to false on a tool that deletes data, causing the LLM to bypass safety
confirmations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ToolAnnotationAbuseCheck(BaseCheck):
    """Tool Annotation Abuse."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement tp025 check logic
        return []
