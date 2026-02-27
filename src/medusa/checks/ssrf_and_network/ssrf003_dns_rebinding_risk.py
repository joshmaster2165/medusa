"""SSRF003: DNS Rebinding Risk.

Detects MCP server tools that validate URLs at request time but do not re-validate after DNS
resolution, making them vulnerable to DNS rebinding attacks. An attacker can configure a DNS
record to first resolve to an allowed IP and then switch to an internal IP between validation
and use.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class DnsRebindingRiskCheck(BaseCheck):
    """DNS Rebinding Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf003 check logic
        return []
