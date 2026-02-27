"""SSRF011: Missing Egress Allowlist.

Detects MCP server deployments that lack an explicit allowlist of permitted external
destinations for tool-initiated network requests. Without an egress allowlist, tools can contact
any external service, making it difficult to detect and prevent data exfiltration or
unauthorized API calls.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingEgressAllowlistCheck(BaseCheck):
    """Missing Egress Allowlist."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement ssrf011 check logic
        return []
