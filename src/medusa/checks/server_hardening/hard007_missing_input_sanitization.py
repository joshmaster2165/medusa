"""HARD007: Missing Server-Level Input Sanitization.

Detects MCP servers that lack a centralized input sanitization layer at the server transport
boundary. Without server-level sanitization, each tool and resource handler must independently
implement input validation, leading to inconsistent protection across the server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_SANITIZATION_KEYS = {
    "sanitize",
    "sanitization",
    "input_validation",
    "input_sanitization",
    "middleware",
    "validator",
    "schema_validation",
    "request_validation",
}


class MissingInputSanitizationCheck(BaseCheck):
    """Missing Server-Level Input Sanitization."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_SANITIZATION_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has no centralized input sanitization configuration. "
                "Each tool must independently validate inputs, risking inconsistent coverage."
            ),
            present_msg=("Server '{server}' has input sanitization or validation configuration."),
            fail_on_present=False,
        )
