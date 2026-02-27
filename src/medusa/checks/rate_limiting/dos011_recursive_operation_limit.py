"""DOS011: Missing Recursive Operation Limit.

Detects MCP server tools that perform recursive operations without depth limits. Unbounded
recursion in file traversal, data processing, dependency resolution, or nested structure parsing
can exhaust stack space and cause server crashes.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_RECURSION_KEYS = {
    "max_depth",
    "max_recursion",
    "recursion_limit",
    "depth_limit",
    "max_nesting",
    "stack_limit",
}
_RECURSION_ENV = {"MAX_RECURSION_DEPTH", "RECURSION_LIMIT", "MAX_DEPTH"}


class RecursiveOperationLimitCheck(BaseCheck):
    """Missing Recursive Operation Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_RECURSION_KEYS,
            env_vars=_RECURSION_ENV,
            missing_msg=(
                "Server '{server}' has no recursion depth limit. "
                "Unbounded recursion can exhaust stack space and crash the server."
            ),
            present_msg="Recursion depth limit configuration detected in: {sources}.",
        )
