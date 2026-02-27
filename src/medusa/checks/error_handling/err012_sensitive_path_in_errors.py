"""ERR012: Sensitive File Paths in Errors.

Detects MCP server error messages that include absolute file paths, revealing the server
installation directory, configuration file locations, temporary file paths, or source code
directory structure on the host system.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SensitivePathInErrorsCheck(BaseCheck):
    """Sensitive File Paths in Errors."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err012 check logic
        return []
