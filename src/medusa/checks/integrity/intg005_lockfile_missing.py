"""INTG005: Missing Package Lockfile.

Detects MCP server projects that lack a package lockfile (e.g. package-lock.json, yarn.lock,
pnpm-lock.yaml, poetry.lock). Without a lockfile, dependency versions are resolved at install
time and may change unexpectedly.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class LockfileMissingCheck(BaseCheck):
    """Missing Package Lockfile."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement intg005 check logic
        return []
