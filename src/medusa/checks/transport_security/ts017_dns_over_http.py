"""TS017: DNS Over HTTP.

Detects MCP server DNS resolution performed over unencrypted HTTP instead of DNS-over-HTTPS
(DoH) or DNS-over-TLS (DoT). Unencrypted DNS queries expose the server's communication targets
to network observers and are vulnerable to DNS spoofing.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DnsOverHttpCheck(BaseCheck):
    """DNS Over HTTP."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ts017 check logic
        return []
