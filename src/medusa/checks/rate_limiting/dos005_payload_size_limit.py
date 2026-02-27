"""DOS005: Missing Payload Size Limit.

Detects MCP server configurations that do not enforce size limits on request and response
payloads. Without size limits, attackers can send oversized requests that consume memory during
parsing or trigger tools to generate massive responses that exhaust server resources.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.rate_limiting.dos001_missing_rate_limiting import _config_check
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding

_PAYLOAD_KEYS = {
    "max_payload_size",
    "max_body_size",
    "max_payload",
    "max_body",
    "body_limit",
    "payload_limit",
    "max_request_size",
    "max_response_size",
    "client_max_body_size",
}
_PAYLOAD_ENV = {"MAX_PAYLOAD_SIZE", "MAX_BODY_SIZE", "BODY_LIMIT"}


class PayloadSizeLimitCheck(BaseCheck):
    """Missing Payload Size Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=_PAYLOAD_KEYS,
            env_vars=_PAYLOAD_ENV,
            missing_msg=(
                "Server '{server}' has no payload size limit configuration. "
                "Oversized requests can exhaust memory during parsing."
            ),
            present_msg="Payload size limit configuration detected in: {sources}.",
        )
