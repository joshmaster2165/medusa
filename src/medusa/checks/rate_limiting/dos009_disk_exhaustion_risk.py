"""DOS009: Disk Exhaustion Risk.

Detects MCP server tools that can fill disk space through writing logs, temporary files, output
data, or uploaded content without storage limits. Disk exhaustion prevents the server from
writing logs, creating temporary files, or processing requests, causing cascading failures.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_DISK_KEYS = {
    "max_disk",
    "disk_limit",
    "storage_limit",
    "max_log_size",
    "disk_quota",
    "max_upload_size",
    "storage_quota",
}
_DISK_ENV = {"MAX_DISK_USAGE", "DISK_LIMIT", "STORAGE_LIMIT", "LOG_MAX_SIZE"}


class DiskExhaustionRiskCheck(BaseCheck):
    """Disk Exhaustion Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_DISK_KEYS,
            env_vars=_DISK_ENV,
            missing_msg=(
                "Server '{server}' has no disk space limit configuration. "
                "Logs, temp files, or uploads may fill disk and cause service failure."
            ),
            present_msg="Disk space limit configuration detected in: {sources}.",
        )
