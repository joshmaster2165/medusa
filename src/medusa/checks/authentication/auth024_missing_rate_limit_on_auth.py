"""AUTH024: Missing Rate Limit on Auth Endpoints.

Detects authentication endpoints without rate limiting or brute-force protection. Endpoints that
accept unlimited authentication attempts allow attackers to perform credential stuffing and
brute-force attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding


class MissingRateLimitOnAuthCheck(BaseCheck):
    """Missing Rate Limit on Auth Endpoints."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        # TODO: Implement auth024 check logic
        return []
