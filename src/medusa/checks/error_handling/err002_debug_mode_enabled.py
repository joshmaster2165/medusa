"""ERR002: Debug Mode Enabled.

Detects MCP servers running with debug or development mode flags enabled in production
environments. Debug mode typically disables security controls, enables verbose logging, exposes
diagnostic endpoints, and may auto-reload code on changes.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DebugModeEnabledCheck(BaseCheck):
    """Debug Mode Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err002 check logic
        return []
