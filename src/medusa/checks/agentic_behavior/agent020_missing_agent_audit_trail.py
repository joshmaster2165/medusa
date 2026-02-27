"""AGENT020: Missing Agent Audit Trail.

Detects MCP configurations that lack comprehensive audit logging of agent decisions, tool
selections, invocation parameters, and outcomes. Without audit trails, it is impossible to
investigate security incidents, detect anomalous behavior, or demonstrate compliance with
security policies.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingAgentAuditTrailCheck(BaseCheck):
    """Missing Agent Audit Trail."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement agent020 check logic
        return []
