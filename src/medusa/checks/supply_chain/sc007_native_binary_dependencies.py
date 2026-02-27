"""SC007: Native Binary Dependencies.

Detects MCP server dependencies that contain prebuilt native binaries. Prebuilt binaries cannot
be audited from source code and may contain hidden functionality.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class NativeBinaryDependenciesCheck(BaseCheck):
    """Native Binary Dependencies."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement sc007 check logic
        return []
