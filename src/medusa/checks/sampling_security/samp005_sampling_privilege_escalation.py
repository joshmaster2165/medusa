"""SAMP005: Privilege Escalation via Sampling.

Detects MCP server implementations where sampling requests can be used to escalate tool access
privileges. A server with limited tool access can use sampling to instruct the LLM to invoke
tools from other servers or access resources beyond the server's authorized scope.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class SamplingPrivilegeEscalationCheck(BaseCheck):
    """Privilege Escalation via Sampling."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement samp005 check logic
        return []
