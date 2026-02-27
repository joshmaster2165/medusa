"""HARD013: Missing Request Validation.

Detects MCP servers that do not validate the structure, content type, and size of incoming
requests at the transport level before processing. Missing request validation allows malformed,
oversized, or incorrectly typed requests to reach application logic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_REQUEST_VALIDATION_KEYS = {
    "request_validation",
    "validate_request",
    "schema_validation",
    "openapi_validation",
    "request_schema",
    "input_validation",
    "request_validator",
}


class MissingRequestValidationCheck(BaseCheck):
    """Missing Request Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_REQUEST_VALIDATION_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has no request validation at the transport level. "
                "Malformed requests may bypass tool-level validation."
            ),
            present_msg=("Server '{server}' has transport-level request validation configured."),
            fail_on_present=False,
        )
