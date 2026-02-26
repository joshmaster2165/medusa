"""AUTH-003: Missing TLS on HTTP Transport.

Flags MCP servers whose transport URL uses plain ``http://`` instead of
``https://``, exposing all traffic to interception and tampering.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}


class MissingTLSCheck(BaseCheck):
    """Check for plain HTTP (no TLS) on HTTP/SSE transports."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()

        # Only applicable to HTTP-based transports.
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []

        # If no URL is available, we cannot determine the scheme.
        if not snapshot.transport_url:
            return []

        parsed = urlparse(snapshot.transport_url)
        scheme = parsed.scheme.lower()

        if scheme == "http":
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
                        f"Server '{snapshot.server_name}' transport URL uses "
                        f"plain HTTP ({snapshot.transport_url}). All traffic "
                        f"including credentials and tool payloads is transmitted "
                        f"in cleartext and can be intercepted."
                    ),
                    evidence=f"transport_url = {snapshot.transport_url}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

        if scheme == "https":
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
                        f"Server '{snapshot.server_name}' transport URL uses "
                        f"HTTPS with TLS encryption."
                    ),
                    evidence=f"transport_url = {snapshot.transport_url}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

        # Unknown scheme -- cannot determine TLS status.
        return []
