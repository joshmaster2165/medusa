"""SESS013: Overly Broad Session Cookie Scope.

Detects MCP servers that set session cookies with overly broad domain or path scopes. Cookies
scoped to parent domains or root paths are sent with requests to all subdomains and paths,
exposing session tokens to unrelated services and increasing the risk of token capture.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_COOKIE_KEYS = {"cookie", "session_cookie", "auth_cookie"}
_REQUIRED_SCOPE_KEYS = {"path", "domain", "samesite"}


def _find_cookie_config(config: dict, depth: int = 0) -> dict | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in _COOKIE_KEYS and isinstance(v, dict):
            return v
        if isinstance(v, dict):
            result = _find_cookie_config(v, depth + 1)
            if result is not None:
                return result
    return None


class SessionCookieScopeCheck(BaseCheck):
    """Overly Broad Session Cookie Scope."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        cookie_config = _find_cookie_config(snapshot.config_raw or {})
        if cookie_config is None:
            return []
        path = cookie_config.get("path", "")
        domain = str(cookie_config.get("domain", ""))
        issues: list[str] = []
        if path == "/":
            issues.append("path='/' (all paths)")
        if domain.startswith("."):
            issues.append(f"domain='{domain}' (all subdomains)")
        if issues:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.cookie_scope",
                    status_extended=(
                        f"Server '{snapshot.server_name}' session cookie has overly broad scope: "
                        f"{'; '.join(issues)}."
                    ),
                    evidence=f"Broad cookie scope: {issues}",
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
                resource_name="session.cookie_scope",
                status_extended=(
                    f"Server '{snapshot.server_name}' session cookie scope appears"
                    f"appropriately restricted."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
