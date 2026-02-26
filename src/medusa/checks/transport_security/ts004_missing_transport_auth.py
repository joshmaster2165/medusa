"""TS-004: Missing Transport Authentication Headers.

Flags HTTP/SSE servers that lack authentication headers (Authorization,
X-API-Key) in their transport configuration.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}

_AUTH_HEADERS = {"authorization", "x-api-key", "cookie", "x-auth-token"}


class MissingTransportAuthCheck(BaseCheck):
    """Check for missing authentication headers on HTTP transports."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()

        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []

        # Look for headers in config_raw
        headers: dict = {}
        if snapshot.config_raw:
            headers = (
                snapshot.config_raw.get("headers")
                or snapshot.config_raw.get("httpHeaders")
                or {}
            )

        if not isinstance(headers, dict):
            headers = {}

        # Check if any auth headers are present
        header_names_lower = {k.lower() for k in headers}
        has_auth = bool(header_names_lower & _AUTH_HEADERS)

        if has_auth:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' has authentication "
                        f"headers configured in its transport configuration."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.FAIL,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    f"Server '{snapshot.server_name}' has no authentication "
                    f"headers (Authorization, X-API-Key) configured in its "
                    f"transport configuration. Requests to this server are "
                    f"unauthenticated at the transport layer."
                ),
                evidence="No auth headers found in transport config",
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
