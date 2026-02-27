"""AUTH010: Missing CSRF Protection.

Detects HTTP transport endpoints without Cross-Site Request Forgery protection. MCP servers
exposed over HTTP without CSRF tokens or same-origin validation are vulnerable to attacks where
a malicious website forces the user's browser to invoke MCP tools.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.authentication import CSRF_CONFIG_KEYS

_HTTP_TRANSPORTS = {"http", "sse"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class MissingCsrfProtectionCheck(BaseCheck):
    """Missing CSRF Protection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_csrf = _walk_config(snapshot.config_raw or {}, CSRF_CONFIG_KEYS)
        if not has_csrf:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="csrf",
                    status_extended=(
                        f"Server '{snapshot.server_name}' HTTP transport has no CSRF protection "
                        f"configured. Cross-site requests can invoke MCP tools without user"
                        f"consent."
                    ),
                    evidence="No csrf/xsrf configuration keys found",
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
                resource_name="csrf",
                status_extended=(
                    f"Server '{snapshot.server_name}' has CSRF protection configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
