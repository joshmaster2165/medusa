"""SSRF004: Unrestricted Network Egress.

Detects MCP server deployments where tools can make outbound network requests to any destination
without egress filtering. Unrestricted egress allows MCP tools to contact arbitrary external
services, exfiltrate data, or establish command-and-control channels.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class UnrestrictedEgressCheck(BaseCheck):
    """Unrestricted Network Egress."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf004 check logic
        return []
