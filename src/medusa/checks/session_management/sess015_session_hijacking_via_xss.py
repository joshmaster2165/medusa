"""SESS015: Session Hijacking via XSS.

Detects MCP server configurations where session tokens are accessible to client-side JavaScript,
making them vulnerable to exfiltration via cross-site scripting (XSS) attacks. If an attacker
injects malicious scripts into the LLM client interface, they can steal session tokens and
hijack the MCP session.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_COOKIE_KEYS = {"cookie", "session_cookie", "auth_cookie", "cookies"}


def _cookie_lacks_httponly(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in _COOKIE_KEYS and isinstance(v, dict):
            httponly = v.get("httponly") or v.get("HttpOnly") or v.get("http_only")
            if not httponly or str(httponly).lower() in ("false", "0", "no"):
                return f"Cookie '{k}' missing HttpOnly flag"
        if isinstance(v, dict):
            result = _cookie_lacks_httponly(v, depth + 1)
            if result:
                return result
    return None


class SessionHijackingViaXssCheck(BaseCheck):
    """Session Hijacking via XSS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence = _cookie_lacks_httponly(snapshot.config_raw or {})
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
                    resource_name="session.httponly",
                    status_extended=(
                        f"Server '{snapshot.server_name}' session cookie lacks HttpOnly flag, "
                        f"making it accessible to JavaScript and vulnerable to XSS theft."
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
                resource_name="session.httponly",
                status_extended=(
                    f"Server '{snapshot.server_name}' session cookie has HttpOnly flag set."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
