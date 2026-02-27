"""SM009: Secrets in Environment Variables.

Detects MCP servers that rely solely on environment variables for secret storage without
additional protection. While better than hardcoding, environment variables are accessible to all
processes running as the same user and are often logged or exposed through process listings and
debug endpoints.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SecretsInEnvironmentVariablesCheck(BaseCheck):
    """Secrets in Environment Variables."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sm009 check logic
        return []
