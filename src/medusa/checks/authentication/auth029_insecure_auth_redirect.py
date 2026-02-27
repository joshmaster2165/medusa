"""AUTH029: Insecure Auth Redirect.

Detects OAuth redirect URI configurations that allow open redirects. When redirect URIs are not
strictly validated, an attacker can redirect the authorization code or token to a malicious
endpoint under their control.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_REDIRECT_KEYS = {
    "redirect_uri",
    "redirect_url",
    "callback_url",
    "callback_uri",
    "return_url",
    "return_uri",
    "post_logout_redirect_uri",
}


def _has_redirect_config(config: dict, depth: int = 0) -> bool:
    """Return True if any redirect-related keys exist in the config."""
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in _REDIRECT_KEYS:
            return True
        if isinstance(v, dict) and _has_redirect_config(v, depth + 1):
            return True
    return False


def _find_http_redirects(config: dict, depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    hits: list[str] = []
    for k, v in config.items():
        if k.lower() in _REDIRECT_KEYS and isinstance(v, str):
            try:
                if urlparse(v).scheme == "http":
                    hits.append(f"'{k}' = '{v}'")
            except Exception:  # noqa: BLE001
                pass
        if isinstance(v, dict):
            hits.extend(_find_http_redirects(v, depth + 1))
    return hits


class InsecureAuthRedirectCheck(BaseCheck):
    """Insecure Auth Redirect."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        config = snapshot.config_raw or {}
        if not _has_redirect_config(config):
            return []
        http_redirects = _find_http_redirects(config)
        if http_redirects:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="oauth.redirect_uri",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has OAuth redirect URI(s) using HTTP: "
                        f"{'; '.join(http_redirects[:3])}. Tokens can be stolen in transit."
                    ),
                    evidence=f"HTTP redirect URIs: {http_redirects[:3]}",
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
                resource_name="oauth.redirect_uri",
                status_extended=(f"Server '{snapshot.server_name}' OAuth redirect URIs use HTTPS."),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
