"""HARD002: Default Configuration in Production.

Detects MCP servers deployed with default configuration values that are intended for development
or testing. Default configurations typically use weak security settings, permissive access
controls, and debug-friendly options that are inappropriate for production.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_DEFAULT_CONFIG_KEYS = {
    "example",
    "sample",
    "default",
    "template",
    "placeholder",
    "demo",
    "test_config",
    "dev_config",
}


class DefaultConfigurationCheck(BaseCheck):
    """Default Configuration in Production."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_DEFAULT_CONFIG_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' config contains default/example configuration keys. "
                "Default configs often use weak or permissive security settings."
            ),
            present_msg=("Server '{server}' does not appear to use default configuration keys."),
            fail_on_present=True,
        )
