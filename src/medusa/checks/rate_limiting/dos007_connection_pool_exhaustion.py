"""DOS007: Connection Pool Exhaustion.

Detects MCP server configurations where connection pools for databases, external APIs, or
internal services can be exhausted by excessive tool invocations. Without connection pool
management, tools that open connections without proper release can deplete available
connections.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_POOL_KEYS = {
    "pool_size",
    "max_connections",
    "connection_pool",
    "pool_max_size",
    "db_pool_size",
    "min_pool",
    "max_pool",
    "pool_timeout",
}
_POOL_ENV = {"DB_POOL_SIZE", "MAX_CONNECTIONS", "POOL_SIZE", "CONNECTION_POOL_SIZE"}


class ConnectionPoolExhaustionCheck(BaseCheck):
    """Connection Pool Exhaustion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_POOL_KEYS,
            env_vars=_POOL_ENV,
            missing_msg=(
                "Server '{server}' has no connection pool configuration. "
                "Excessive tool invocations may deplete available connections."
            ),
            present_msg="Connection pool configuration detected in: {sources}.",
        )
