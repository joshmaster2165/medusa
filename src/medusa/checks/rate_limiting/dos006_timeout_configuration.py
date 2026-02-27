"""DOS006: Missing Timeout Configuration.

Detects MCP server tools that execute without configured timeouts. Missing timeouts allow tool
invocations to run indefinitely, consuming server resources and blocking processing capacity for
other requests. Long-running tools can be intentionally triggered as a denial-of-service
technique.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_TIMEOUT_KEYS = {
    "timeout",
    "connection_timeout",
    "read_timeout",
    "write_timeout",
    "request_timeout",
    "idle_timeout",
    "keep_alive_timeout",
    "execution_timeout",
    "tool_timeout",
}
_TIMEOUT_ENV = {"TIMEOUT", "REQUEST_TIMEOUT", "CONNECTION_TIMEOUT", "TOOL_TIMEOUT"}


class TimeoutConfigurationCheck(BaseCheck):
    """Missing Timeout Configuration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_TIMEOUT_KEYS,
            env_vars=_TIMEOUT_ENV,
            missing_msg=(
                "Server '{server}' has no timeout configuration. "
                "Tool invocations may run indefinitely, blocking server capacity."
            ),
            present_msg="Timeout configuration detected in: {sources}.",
        )
