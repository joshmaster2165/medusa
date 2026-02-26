"""AUTH-001: No Authentication on HTTP Transport.

Detects MCP servers exposed over HTTP or SSE without any authentication
mechanism configured (e.g. no Authorization header, no OAuth, no API key).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}

# Config keys that indicate authentication is present.
_AUTH_CONFIG_KEYS = {"auth", "authorization", "headers", "oauth", "api_key", "apiKey"}


def _config_has_auth(config: dict | None) -> tuple[bool, str]:
    """Walk the config dict looking for authentication-related keys.

    Returns (has_auth, evidence_description).
    """
    if not config:
        return False, "No configuration provided"

    # Check top-level keys.
    for key in config:
        if key.lower() in _AUTH_CONFIG_KEYS:
            return True, f"Authentication config found at key '{key}'"

    # Check nested 'headers' for Authorization.
    headers = config.get("headers") or config.get("httpHeaders") or {}
    if isinstance(headers, dict):
        for header_name in headers:
            if header_name.lower() in ("authorization", "x-api-key"):
                return True, f"Auth header '{header_name}' configured"

    # Check for OAuth blocks nested under transport/server settings.
    for key, value in config.items():
        if isinstance(value, dict):
            for nested_key in value:
                if nested_key.lower() in _AUTH_CONFIG_KEYS:
                    return True, f"Authentication config found at '{key}.{nested_key}'"

    return False, "No authentication configuration detected"


class NoAuthenticationCheck(BaseCheck):
    """Check for HTTP/SSE MCP servers with no authentication."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()

        # Only applicable to HTTP-based transports.
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []

        has_auth, evidence = _config_has_auth(snapshot.config_raw)

        if has_auth:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' has authentication "
                        f"configured on its {snapshot.transport_type.upper()} transport."
                    ),
                    evidence=evidence,
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.FAIL,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    f"Server '{snapshot.server_name}' is exposed over "
                    f"{snapshot.transport_type.upper()} with no authentication. "
                    f"Any network-reachable client can invoke its tools and "
                    f"access its resources."
                ),
                evidence=evidence,
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
