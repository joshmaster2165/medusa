"""AUTH013: Insecure Cookie Flags.

Detects authentication cookies missing security flags such as Secure, HttpOnly, and SameSite.
Cookies without these flags are vulnerable to interception over unencrypted connections, cross-
site scripting theft, and cross-site request forgery.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_COOKIE_KEYS = {"cookie", "session_cookie", "auth_cookie", "cookies"}
_REQUIRED_FLAGS = {"secure", "httponly", "samesite"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> dict | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in keys and isinstance(v, dict):
            return v
        if isinstance(v, dict):
            result = _walk_config(v, keys, depth + 1)
            if result is not None:
                return result
    return None


class InsecureCookieFlagsCheck(BaseCheck):
    """Insecure Cookie Flags."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        cookie_config = _walk_config(snapshot.config_raw or {}, _COOKIE_KEYS)
        if cookie_config is None:
            return []
        cookie_keys_lower = {k.lower() for k in cookie_config}
        missing = _REQUIRED_FLAGS - cookie_keys_lower
        if missing:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="cookie",
                    status_extended=(
                        f"Server '{snapshot.server_name}' cookie configuration is missing "
                        f"security flags: {', '.join(sorted(missing))}."
                    ),
                    evidence=f"Missing cookie flags: {sorted(missing)}",
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
                resource_name="cookie",
                status_extended=(
                    f"Server '{snapshot.server_name}' cookie flags include Secure, HttpOnly,"
                    f"SameSite."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
