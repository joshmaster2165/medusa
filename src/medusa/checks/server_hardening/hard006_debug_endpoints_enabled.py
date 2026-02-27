"""HARD006: Debug Endpoints Enabled.

Detects MCP servers that expose debug or diagnostic endpoints in production deployments. Debug
endpoints may include health checks with internal details, profiling endpoints, memory dumps, or
configuration inspection endpoints that reveal sensitive internals.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.pattern_matching import DEBUG_CONFIG_KEYS

_DEBUG_ENDPOINT_KEYS = DEBUG_CONFIG_KEYS | {
    "debug_endpoint",
    "pprof",
    "metrics_endpoint",
    "profiling_endpoint",
    "heap_dump",
    "thread_dump",
}


class DebugEndpointsEnabledCheck(BaseCheck):
    """Debug Endpoints Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_DEBUG_ENDPOINT_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has debug endpoints or profiling enabled in configuration. "
                "These expose internal state and should be disabled in production."
            ),
            present_msg=("Server '{server}' does not appear to have debug endpoints enabled."),
            fail_on_present=True,
        )
