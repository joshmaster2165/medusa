"""SESS004: Session ID Stored in URL.

Detects MCP server configurations where session identifiers are transmitted or stored in URL
parameters rather than secure headers or cookies. Session IDs in URLs are exposed in browser
history, server logs, referrer headers, and proxy logs, making them trivially accessible to
attackers.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_PARAMS = {"session_id", "sessionid", "session", "sid", "jsessionid", "phpsessid"}


def _url_has_session_param(url: str) -> str | None:
    try:
        params = parse_qs(urlparse(url).query)
        for p in params:
            if p.lower() in _SESSION_PARAMS:
                return p
    except Exception:  # noqa: BLE001
        pass
    return None


def _config_has_session_in_url(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if isinstance(v, str) and ("http" in v or "https" in v):
            param = _url_has_session_param(v)
            if param:
                return f"Config key '{k}' URL contains session param '{param}'"
        if isinstance(v, dict):
            result = _config_has_session_in_url(v, depth + 1)
            if result:
                return result
    return None


class SessionStoredInUrlCheck(BaseCheck):
    """Session ID Stored in URL."""

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
            param = _url_has_session_param(snapshot.transport_url)
            if param:
                evidence = f"transport_url contains session param '{param}'"
        if not evidence and snapshot.config_raw:
            evidence = _config_has_session_in_url(snapshot.config_raw)
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
                    resource_name="session.url_exposure",
                    status_extended=(
                        f"Server '{snapshot.server_name}' passes session ID in URL parameters, "
                        f"exposing it in logs, history, and referrer headers."
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
                resource_name="session.url_exposure",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not expose session IDs in URLs."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
