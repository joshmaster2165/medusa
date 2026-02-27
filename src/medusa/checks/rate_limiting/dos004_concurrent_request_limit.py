"""DOS004: Missing Concurrent Request Limit.

Detects MCP server configurations that allow unlimited concurrent requests from a single client
or across all clients. Without concurrent request limits, server threads, connections, and
processing capacity can be exhausted by parallel requests from aggressive LLM agents.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_CONCURRENCY_KEYS = {
    "concurrency",
    "max_concurrent",
    "max_concurrent_requests",
    "worker_threads",
    "thread_pool",
    "max_workers",
    "semaphore",
}
_CONCURRENCY_ENV = {"MAX_CONCURRENT", "CONCURRENCY_LIMIT", "WORKER_THREADS"}


class ConcurrentRequestLimitCheck(BaseCheck):
    """Missing Concurrent Request Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_CONCURRENCY_KEYS,
            env_vars=_CONCURRENCY_ENV,
            missing_msg=(
                "Server '{server}' has no concurrent request limit configuration. "
                "Parallel LLM agent requests can exhaust server capacity."
            ),
            present_msg="Concurrent request limit configuration detected in: {sources}.",
        )
