"""AUTH017: API Key in Insecure Headers.

Detects API keys transmitted in non-standard or commonly logged HTTP headers. Using headers like
X-Api-Key without TLS, or placing keys in headers that proxy servers and load balancers
routinely log, exposes credentials to interception.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_API_KEY_HEADERS = {"x-api-key", "api-key", "x-auth-token", "apikey", "x-token"}


def _has_api_key_header(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    headers = config.get("headers") or config.get("httpHeaders") or {}
    if isinstance(headers, dict):
        for h in headers:
            if h.lower() in _API_KEY_HEADERS:
                return h
    for k, v in config.items():
        if isinstance(v, dict):
            result = _has_api_key_header(v, depth + 1)
            if result:
                return result
    return None


class ApiKeyInHeadersInsecureCheck(BaseCheck):
    """API Key in Insecure Headers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        api_key_header = _has_api_key_header(snapshot.config_raw or {})
        if not api_key_header:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="headers.api_key",
                    status_extended=(
                        f"Server '{snapshot.server_name}' does not use API key headers."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        # API key in headers is only insecure over plain HTTP
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
                    resource_name=f"headers.{api_key_header}",
                    status_extended=(
                        f"Server '{snapshot.server_name}' transmits API key in header "
                        f"'{api_key_header}' over plain HTTP, exposing it to interception."
                    ),
                    evidence=f"API key header '{api_key_header}' used with HTTP transport",
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
                resource_name=f"headers.{api_key_header}",
                status_extended=(
                    f"Server '{snapshot.server_name}' API key header is transmitted over HTTPS."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
