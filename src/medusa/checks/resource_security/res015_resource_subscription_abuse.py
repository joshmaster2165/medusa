"""RES015: Resource Subscription Abuse.

Detects MCP resource subscription endpoints that lack rate limiting, maximum subscription
counts, or client validation. Uncontrolled subscriptions can exhaust server resources through
notification flooding or enable unauthorized real-time data monitoring.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class ResourceSubscriptionAbuseCheck(BaseCheck):
    """Resource Subscription Abuse."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement res015 check logic
        return []
