"""AUTH-004: Localhost Binding Without Authentication.

Flags MCP servers bound to localhost/127.0.0.1 over HTTP/SSE without
authentication, which are vulnerable to DNS rebinding attacks.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}

_LOCALHOST_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "[::1]",
    "0.0.0.0",
}

# Config keys that indicate authentication is present (shared with AUTH-001).
_AUTH_CONFIG_KEYS = {"auth", "authorization", "headers", "oauth", "api_key", "apiKey"}


def _is_localhost(url: str | None) -> bool:
    """Determine whether the URL points to a localhost address."""
    if not url:
        return False
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    return hostname in _LOCALHOST_HOSTS


def _config_has_auth(config: dict | None) -> bool:
    """Quick check for any authentication-related configuration."""
    if not config:
        return False

    for key in config:
        if key.lower() in _AUTH_CONFIG_KEYS:
            return True

    # Check nested headers.
    headers = config.get("headers") or config.get("httpHeaders") or {}
    if isinstance(headers, dict):
        for header_name in headers:
            if header_name.lower() in ("authorization", "x-api-key"):
                return True

    # Check nested dicts.
    for key, value in config.items():
        if isinstance(value, dict):
            for nested_key in value:
                if nested_key.lower() in _AUTH_CONFIG_KEYS:
                    return True

    return False


class LocalhostNoAuthCheck(BaseCheck):
    """Check for localhost-bound HTTP servers without authentication."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()

        # Only applicable to HTTP-based transports.
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []

        # Only applicable to localhost-bound servers.
        if not _is_localhost(snapshot.transport_url):
            return []

        has_auth = _config_has_auth(snapshot.config_raw)

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
                        f"Server '{snapshot.server_name}' is bound to localhost "
                        f"and has authentication configured, mitigating DNS "
                        f"rebinding risks."
                    ),
                    evidence=f"transport_url = {snapshot.transport_url}",
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
                    f"Server '{snapshot.server_name}' is bound to localhost "
                    f"({snapshot.transport_url}) without authentication. This is "
                    f"vulnerable to DNS rebinding attacks where a malicious "
                    f"website can make requests to the local MCP server through "
                    f"the user's browser."
                ),
                evidence=(
                    f"transport_url = {snapshot.transport_url}; "
                    f"authentication = none detected"
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
