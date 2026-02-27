"""ERR003: Verbose Error Messages.

Detects MCP server error responses that include overly detailed messages revealing internal
implementation specifics such as database table names, query structures, internal API endpoints,
configuration values, or third-party service identifiers.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class VerboseErrorMessagesCheck(BaseCheck):
    """Verbose Error Messages."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement err003 check logic
        return []
