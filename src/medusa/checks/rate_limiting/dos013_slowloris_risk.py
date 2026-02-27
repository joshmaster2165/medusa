"""DOS013: Slowloris Attack Risk.

Detects MCP server configurations vulnerable to slowloris-style attacks where clients send
requests extremely slowly, holding connections open for extended periods. Slow connections
consume server connection slots without generating meaningful load, exhausting the server's
ability to accept new connections.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_SLOWLORIS_KEYS = {
    "header_timeout",
    "slow_connection_timeout",
    "client_header_timeout",
    "client_body_timeout",
    "keepalive_timeout",
    "lingering_timeout",
    "min_request_rate",
}
_SLOWLORIS_ENV = {"HEADER_TIMEOUT", "CLIENT_TIMEOUT", "KEEPALIVE_TIMEOUT"}


class SlowlorisRiskCheck(BaseCheck):
    """Slowloris Attack Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_SLOWLORIS_KEYS,
            env_vars=_SLOWLORIS_ENV,
            missing_msg=(
                "Server '{server}' has no slow connection timeout configuration. "
                "Slow-read clients can hold connections open and exhaust server slots."
            ),
            present_msg="Slow connection timeout configuration detected in: {sources}.",
        )
