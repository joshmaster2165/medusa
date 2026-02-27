"""TS014: WebSocket Without TLS.

Detects MCP server WebSocket connections using ws:// instead of wss://. Unencrypted WebSocket
connections expose all bidirectional communication to network-level interception, including tool
invocations, responses, and authentication tokens.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}


def _find_ws_url(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if isinstance(v, str) and v.startswith("ws://"):
            return f"'{k}' = '{v}'"
        if isinstance(v, dict):
            result = _find_ws_url(v, depth + 1)
            if result:
                return result
    return None


class WebsocketWithoutTlsCheck(BaseCheck):
    """WebSocket Without TLS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence: str | None = None
        if snapshot.transport_url and snapshot.transport_url.startswith("ws://"):
            evidence = f"transport_url = '{snapshot.transport_url}'"
        if not evidence and snapshot.config_raw:
            evidence = _find_ws_url(snapshot.config_raw)
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
                    resource_name="websocket.url",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses unencrypted WebSocket (ws://). "
                        f"All communication is exposed to network interception."
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
                resource_name="websocket.url",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not use unencrypted WebSocket"
                    f"connections."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
