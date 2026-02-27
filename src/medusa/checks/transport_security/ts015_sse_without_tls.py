"""TS015: SSE Without TLS.

Detects Server-Sent Events (SSE) connections over unencrypted HTTP. MCP servers using SSE
transport over HTTP expose the event stream to network interception, including tool results,
notifications, and potentially sensitive server-pushed data.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SSE_TRANSPORTS = {"sse"}
_HTTP_TRANSPORTS = {"http", "sse"}


class SseWithoutTlsCheck(BaseCheck):
    """SSE Without TLS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _SSE_TRANSPORTS:
            return []
        is_http = False
        if snapshot.transport_url:
            try:
                is_http = urlparse(snapshot.transport_url).scheme == "http"
            except Exception:  # noqa: BLE001
                pass
        if is_http:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="sse.url",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses SSE over unencrypted HTTP "
                        f"({snapshot.transport_url}). Event stream is exposed to interception."
                    ),
                    evidence=f"SSE transport_url uses HTTP: {snapshot.transport_url}",
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
                resource_name="sse.url",
                status_extended=(f"Server '{snapshot.server_name}' SSE transport uses HTTPS."),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
