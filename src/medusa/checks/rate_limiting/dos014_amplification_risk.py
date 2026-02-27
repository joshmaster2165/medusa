"""DOS014: Amplification Attack Risk.

Detects MCP server tools where small input requests generate disproportionately large responses
or trigger extensive downstream processing. Amplification allows an attacker to consume server
and network resources far exceeding the cost of their requests.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_AMPLIFICATION_KEYS = {
    "max_response_size",
    "response_limit",
    "max_fanout",
    "amplification_limit",
    "downstream_timeout",
    "max_sub_requests",
}
_AMPLIFICATION_ENV = {"MAX_RESPONSE_SIZE", "RESPONSE_SIZE_LIMIT", "MAX_FANOUT"}


class AmplificationRiskCheck(BaseCheck):
    """Amplification Attack Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_AMPLIFICATION_KEYS,
            env_vars=_AMPLIFICATION_ENV,
            missing_msg=(
                "Server '{server}' has no amplification limit configuration. "
                "Small inputs may generate disproportionately large downstream requests."
            ),
            present_msg="Amplification limit configuration detected in: {sources}.",
        )
