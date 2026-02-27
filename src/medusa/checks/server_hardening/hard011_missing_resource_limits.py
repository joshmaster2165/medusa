"""HARD011: Missing Server Resource Limits.

Detects MCP servers that do not enforce limits on system resource consumption including memory
usage, CPU time, file descriptor count, disk space, and network connections. Without resource
limits, a single request can consume all available server resources.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.pattern_matching import RESOURCE_LIMIT_KEYS


class MissingResourceLimitsCheck(BaseCheck):
    """Missing Server Resource Limits."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=RESOURCE_LIMIT_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has no server resource limit configuration. "
                "A single request can consume all available system resources."
            ),
            present_msg=("Server '{server}' has resource limit configuration."),
            fail_on_present=False,
        )
