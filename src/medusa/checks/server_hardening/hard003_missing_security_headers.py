"""HARD003: Missing Security Headers.

Detects MCP servers using HTTP-based transports that do not set security-relevant response
headers such as Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security,
X-Frame-Options, and Cache-Control for sensitive responses.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.server_hardening.hard001_unnecessary_services_enabled import (
    _hardening_config_check,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding
from medusa.utils.pattern_matching import CSP_CONFIG_KEYS, HSTS_CONFIG_KEYS

_SECURITY_HEADER_KEYS = (
    CSP_CONFIG_KEYS
    | HSTS_CONFIG_KEYS
    | {
        "x_content_type_options",
        "x_frame_options",
        "security_headers",
        "headers",
        "x-content-type-options",
        "x-frame-options",
        "strict-transport-security",
        "content-security-policy",
    }
)


class MissingSecurityHeadersCheck(BaseCheck):
    """Missing Security Headers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        # Only applicable to HTTP transports
        if snapshot.transport_type == "stdio":
            return []
        return _hardening_config_check(
            snapshot,
            meta,
            bad_keys=_SECURITY_HEADER_KEYS,
            bad_values=None,
            missing_msg=(
                "Server '{server}' has no security header configuration. "
                "HTTP responses may lack CSP, HSTS, and other protective headers."
            ),
            present_msg=("Server '{server}' has security header configuration present."),
            fail_on_present=False,
        )
