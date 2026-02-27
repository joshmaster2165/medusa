"""SM014: Secrets in Log Output.

Detects MCP servers that include secrets in log output, whether in application logs, access
logs, error logs, or debug logs. Logged secrets are exposed to anyone with log access and
persist in log storage systems indefinitely.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SecretsInLogsCheck(BaseCheck):
    """Secrets in Log Output."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sm014 check logic
        return []
