"""SSRF016: Missing Request Timeout.

Detects MCP server tools that make network requests without configuring timeouts. Missing
timeouts allow requests to hang indefinitely, consuming server resources and potentially
enabling denial-of-service attacks through slow-response techniques or connection exhaustion.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingRequestTimeoutCheck(BaseCheck):
    """Missing Request Timeout."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf016 check logic
        return []
