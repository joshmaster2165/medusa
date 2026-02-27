"""AUTH020: Missing Authorization Header.

Detects MCP servers using HTTP transport without any Authorization header configuration. Servers
that do not expect or validate Authorization headers accept all requests as authenticated,
providing no access control.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.authentication import AUTH_HEADER_NAMES

_HTTP_TRANSPORTS = {"http", "sse"}


def _has_auth_header(config: dict, depth: int = 0) -> bool:
    if depth > 10:
        return False
    headers = config.get("headers") or config.get("httpHeaders") or {}
    if isinstance(headers, dict):
        for h in headers:
            if h.lower() in AUTH_HEADER_NAMES:
                return True
    for k, v in config.items():
        if isinstance(v, dict) and _has_auth_header(v, depth + 1):
            return True
    return False


class MissingAuthHeaderCheck(BaseCheck):
    """Missing Authorization Header."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_auth = _has_auth_header(snapshot.config_raw or {})
        if not has_auth:
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
                        f"Server '{snapshot.server_name}' HTTP transport has no Authorization "
                        f"header configured. All requests are accepted without authentication."
                    ),
                    evidence="No authorization/x-api-key header found in config",
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
                status_extended=(
                    f"Server '{snapshot.server_name}' has Authorization header configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
