"""AUTH021: Basic Auth Over HTTP.

Detects HTTP Basic authentication used over unencrypted HTTP connections. Basic auth transmits
credentials as base64-encoded plaintext, which is trivially decoded by any network observer when
TLS is not used.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}


def _has_basic_auth(config: dict, depth: int = 0) -> bool:
    if depth > 10:
        return False
    headers = config.get("headers") or config.get("httpHeaders") or {}
    if isinstance(headers, dict):
        auth_value = headers.get("Authorization") or headers.get("authorization") or ""
        if isinstance(auth_value, str) and auth_value.lower().startswith("basic "):
            return True
    for k, v in config.items():
        if k.lower() in ("username", "user", "login") and isinstance(v, str):
            return True
        if isinstance(v, dict) and _has_basic_auth(v, depth + 1):
            return True
    return False


class BasicAuthOverHttpCheck(BaseCheck):
    """Basic Auth Over HTTP."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_basic = _has_basic_auth(snapshot.config_raw or {})
        if not has_basic:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="headers.Authorization",
                    status_extended=(
                        f"Server '{snapshot.server_name}' does not use HTTP Basic authentication."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        is_http = False
        if snapshot.transport_url:
            try:
                is_http = urlparse(snapshot.transport_url).scheme == "http"
            except Exception:  # noqa: BLE001
                pass
        if is_http:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="headers.Authorization",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses HTTP Basic authentication over "
                        f"unencrypted HTTP. Credentials are transmitted as base64 plaintext."
                    ),
                    evidence="Basic auth used with HTTP (not HTTPS) transport",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="config",
                resource_name="headers.Authorization",
                status_extended=(f"Server '{snapshot.server_name}' Basic auth is used over HTTPS."),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
