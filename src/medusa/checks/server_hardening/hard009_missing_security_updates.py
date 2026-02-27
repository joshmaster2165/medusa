"""HARD009: Missing Security Updates.

Detects MCP servers running outdated versions of their runtime, framework, or dependencies that
have known security vulnerabilities. Missing security patches leave the server exposed to
publicly disclosed exploits with available proof-of-concept code.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_UPDATE_KEYS = {
    "auto_update",
    "automatic_updates",
    "security_updates",
    "patch_management",
    "update_check",
    "auto_patch",
}


class MissingSecurityUpdatesCheck(BaseCheck):
    """Missing Security Updates."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_UPDATE_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has no automated security update configuration. "
                "Outdated dependencies may contain known exploitable vulnerabilities."
            ),
            present_msg=("Server '{server}' has automated security update configuration."),
            fail_on_present=False,
        )
