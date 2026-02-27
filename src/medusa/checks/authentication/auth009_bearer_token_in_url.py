"""AUTH009: Bearer Token in URL Parameters.

Detects authentication tokens passed via URL query string parameters instead of HTTP headers.
Tokens in URLs are logged in server access logs, browser history, proxy logs, and referrer
headers, creating multiple exposure vectors.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SENSITIVE_PARAMS = {
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "bearer",
    "auth",
    "authorization",
    "secret",
    "credential",
}


def _url_has_token_param(url: str) -> str | None:
    """Return the offending param name if token appears in URL query string."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            if param.lower() in _SENSITIVE_PARAMS:
                return param
    except Exception:  # noqa: BLE001
        pass
    return None


def _config_has_token_in_url(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if isinstance(v, str) and ("http" in v.lower() or "https" in v.lower()):
            result = _url_has_token_param(v)
            if result:
                return f"Key '{k}' URL contains token param '{result}'"
        if isinstance(v, dict):
            result = _config_has_token_in_url(v, depth + 1)
            if result:
                return result
    return None


class BearerTokenInUrlCheck(BaseCheck):
    """Bearer Token in URL Parameters."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence: str | None = None
        if snapshot.transport_url:
            param = _url_has_token_param(snapshot.transport_url)
            if param:
                evidence = f"transport_url contains sensitive query param '{param}'"
        if not evidence and snapshot.config_raw:
            evidence = _config_has_token_in_url(snapshot.config_raw)
        if evidence:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="transport_url",
                    status_extended=(
                        f"Server '{snapshot.server_name}' passes authentication tokens "
                        f"in URL query parameters, exposing them in logs and history."
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
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="config",
                resource_name="transport_url",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not expose tokens in URL parameters."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
