"""AUTH023: Shared Secrets Across Servers.

Detects identical credentials or API keys used across multiple MCP servers. Sharing secrets
across servers means that a compromise of one server exposes all servers using the same
credential.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SharedSecretsAcrossServersCheck(BaseCheck):
    """Shared Secrets Across Servers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth023 check logic
        return []
