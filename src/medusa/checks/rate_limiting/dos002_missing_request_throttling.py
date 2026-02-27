"""DOS002: Missing Request Throttling.

Detects MCP server API endpoints that lack request throttling mechanisms. Without throttling,
burst traffic from LLM agents can saturate server capacity, degrading performance for all
connected clients and potentially causing service outages.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.pattern_matching import RATE_LIMIT_CONFIG_KEYS, RATE_LIMIT_ENV_VARS

_THROTTLE_KEYS = {
    "throttle",
    "throttling",
    "burst",
    "burst_limit",
    "requests_per_second",
    "requests_per_minute",
    "req_per_sec",
    "rps_limit",
}
_THROTTLE_ENV = {"THROTTLE_LIMIT", "BURST_LIMIT", "MAX_RPS"}


class MissingRequestThrottlingCheck(BaseCheck):
    """Missing Request Throttling."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_THROTTLE_KEYS | RATE_LIMIT_CONFIG_KEYS,
            env_vars=_THROTTLE_ENV | RATE_LIMIT_ENV_VARS,
            missing_msg=(
                "Server '{server}' has no request throttling configuration. "
                "Burst traffic from LLM agents can exhaust capacity."
            ),
            present_msg="Request throttling configuration detected in: {sources}.",
        )
