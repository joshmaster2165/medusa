"""HARD005: Admin Interface Exposed.

Detects MCP servers that expose administrative or management interfaces to the same network or
transport as client-facing endpoints. Admin interfaces provide elevated capabilities including
server configuration, user management, and diagnostic access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_ADMIN_KEYS = {
    "admin",
    "admin_interface",
    "admin_panel",
    "management_interface",
    "admin_endpoint",
    "admin_port",
    "admin_url",
    "admin_path",
    "management",
    "management_port",
}


class AdminInterfaceExposedCheck(BaseCheck):
    """Admin Interface Exposed."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_ADMIN_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' exposes an admin interface in its configuration. "
                "Admin interfaces should be on isolated networks or disabled."
            ),
            present_msg=("Server '{server}' does not appear to expose an admin interface."),
            fail_on_present=True,
        )
