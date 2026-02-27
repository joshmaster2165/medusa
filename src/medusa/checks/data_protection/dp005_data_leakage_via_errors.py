"""DP005: Data Leakage via Error Messages.

Detects MCP servers that expose sensitive data in error responses. Stack traces, database
connection strings, internal paths, and debug information returned in error messages can reveal
implementation details and secrets to untrusted LLM clients.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DataLeakageViaErrorsCheck(BaseCheck):
    """Data Leakage via Error Messages."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement dp005 check logic
        return []
