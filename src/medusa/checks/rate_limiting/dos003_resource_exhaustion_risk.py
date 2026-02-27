"""DOS003: Resource Exhaustion Risk.

Detects MCP server tools that can consume unbounded system resources during execution. Tools
that process large inputs, perform complex computations, or interact with external services
without resource limits can exhaust server capacity and affect all connected sessions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.pattern_matching import RESOURCE_LIMIT_KEYS

_RESOURCE_ENV = {"MAX_MEMORY", "MAX_CPU", "ULIMIT", "RESOURCE_LIMIT"}


class ResourceExhaustionRiskCheck(BaseCheck):
    """Resource Exhaustion Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=RESOURCE_LIMIT_KEYS,
            env_vars=_RESOURCE_ENV,
            missing_msg=(
                "Server '{server}' has no resource limit configuration. "
                "Tool execution may exhaust CPU, memory, or I/O."
            ),
            present_msg="Resource limit configuration detected in: {sources}.",
        )
