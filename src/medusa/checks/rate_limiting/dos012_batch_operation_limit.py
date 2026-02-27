"""DOS012: Missing Batch Operation Limit.

Detects MCP server tools that accept batch operations without limiting the batch size. Unbounded
batch sizes allow a single tool invocation to process an arbitrary number of items, consuming
disproportionate resources compared to a single invocation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_BATCH_KEYS = {
    "batch_size",
    "max_batch_size",
    "max_items",
    "page_size",
    "max_page_size",
    "chunk_size",
    "batch_limit",
}
_BATCH_ENV = {"MAX_BATCH_SIZE", "BATCH_LIMIT", "MAX_ITEMS_PER_REQUEST"}


class BatchOperationLimitCheck(BaseCheck):
    """Missing Batch Operation Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_BATCH_KEYS,
            env_vars=_BATCH_ENV,
            missing_msg=(
                "Server '{server}' has no batch operation size limit. "
                "A single invocation could process an unbounded number of items."
            ),
            present_msg="Batch operation limit configuration detected in: {sources}.",
        )
