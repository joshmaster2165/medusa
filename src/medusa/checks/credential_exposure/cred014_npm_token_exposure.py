"""CRED014: NPM Token Exposure.

Detects NPM authentication tokens in .npmrc files, environment variables, or MCP server
configuration. NPM tokens grant permissions to publish, modify, and manage packages in the npm
registry.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class NpmTokenExposureCheck(BaseCheck):
    """NPM Token Exposure."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement cred014 check logic
        return []
