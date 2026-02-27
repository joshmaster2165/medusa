"""DOS008: Memory Exhaustion Risk.

Detects MCP server tools that can cause memory exhaustion through processing large datasets,
accumulating results in memory, or triggering memory leaks. Memory exhaustion crashes the server
process and terminates all active sessions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_MEMORY_KEYS = {
    "max_memory",
    "memory_limit",
    "heap_size",
    "max_heap",
    "memory_quota",
    "jvm_max_heap",
    "node_max_old_space",
}
_MEMORY_ENV = {
    "MAX_MEMORY",
    "MEMORY_LIMIT",
    "NODE_OPTIONS",
    "JVM_OPTS",
    "JAVA_OPTS",
    "NODE_MAX_OLD_SPACE_SIZE",
}


class MemoryExhaustionRiskCheck(BaseCheck):
    """Memory Exhaustion Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_MEMORY_KEYS,
            env_vars=_MEMORY_ENV,
            missing_msg=(
                "Server '{server}' has no memory limit configuration. "
                "Processing large datasets can exhaust memory and crash the server."
            ),
            present_msg="Memory limit configuration detected in: {sources}.",
        )
