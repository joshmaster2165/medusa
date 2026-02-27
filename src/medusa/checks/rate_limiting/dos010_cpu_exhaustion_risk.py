"""DOS010: CPU Exhaustion Risk.

Detects MCP server tools that can cause excessive CPU usage through computationally intensive
operations such as complex regex evaluation, cryptographic operations, data transformation, or
algorithmic processing without CPU time limits.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_CPU_KEYS = {
    "max_cpu",
    "cpu_limit",
    "cpu_quota",
    "cpu_shares",
    "cpu_period",
    "cpu_time_limit",
    "process_priority",
}
_CPU_ENV = {"MAX_CPU", "CPU_LIMIT", "CPU_QUOTA", "CPU_SHARES"}


class CpuExhaustionRiskCheck(BaseCheck):
    """CPU Exhaustion Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_CPU_KEYS,
            env_vars=_CPU_ENV,
            missing_msg=(
                "Server '{server}' has no CPU limit configuration. "
                "Computationally intensive tool operations may starve other processes."
            ),
            present_msg="CPU limit configuration detected in: {sources}.",
        )
