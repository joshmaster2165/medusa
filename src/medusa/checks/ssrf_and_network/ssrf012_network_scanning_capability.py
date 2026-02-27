"""SSRF012: Network Scanning Capability.

Detects MCP server tools that can be abused to perform network scanning by making requests to
arbitrary hosts and analyzing response characteristics. Tools that accept hostnames or IP
addresses as parameters can be systematically used to discover live hosts on internal networks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class NetworkScanningCapabilityCheck(BaseCheck):
    """Network Scanning Capability."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf012 check logic
        return []
