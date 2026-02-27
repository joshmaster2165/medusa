"""AUTH011: Hardcoded Credentials in Config.

Detects username and password pairs, API keys, and other credentials hardcoded directly in MCP
server configuration files or source code. Hardcoded credentials cannot be rotated without code
changes and are trivially extracted from the codebase.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class HardcodedCredentialsCheck(BaseCheck):
    """Hardcoded Credentials in Config."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth011 check logic
        return []
