"""SSRF017: Unbounded Redirect Chain.

Detects MCP server tools that follow HTTP redirects without limiting the number of redirects in
a chain. Unbounded redirect following can lead to infinite redirect loops, excessive resource
consumption, and redirect-based SSRF attacks that gradually move through allowed domains to
reach blocked targets.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnboundedRedirectChainCheck(BaseCheck):
    """Unbounded Redirect Chain."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf017 check logic
        return []
