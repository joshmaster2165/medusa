"""HARD012: Unnecessary HTTP Methods Enabled.

Detects MCP servers using HTTP-based transports that accept HTTP methods beyond those required
for MCP operation. Methods such as TRACE, OPTIONS, PUT, DELETE, and PATCH may be enabled by
default but are not needed for standard MCP communication.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_UNSAFE_METHOD_KEYS = {
    "allowed_methods",
    "http_methods",
    "trace",
    "options_method",
    "allow_trace",
    "allow_delete",
    "enable_delete",
}


class UnnecessaryHttpMethodsCheck(BaseCheck):
    """Unnecessary HTTP Methods Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type == "stdio":
            return []
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_UNSAFE_METHOD_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' does not restrict HTTP methods in configuration. "
                "TRACE, DELETE, and PUT may be enabled by default."
            ),
            present_msg=("Server '{server}' has HTTP method restriction configured."),
            fail_on_present=False,
        )
