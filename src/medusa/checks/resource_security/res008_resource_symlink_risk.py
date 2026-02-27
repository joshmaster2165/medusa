"""RES008: Resource Symlink Following.

Detects MCP file-based resource handlers that follow symbolic links without validation, allowing
attackers to create symlinks that point to files outside the intended resource directory. This
enables reading arbitrary files on the server file system.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceSymlinkRiskCheck(BaseCheck):
    """Resource Symlink Following."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res008 check logic
        return []
