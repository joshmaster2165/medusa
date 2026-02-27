"""TS005: Mixed Content Transport.

Detects MCP servers that mix HTTP and HTTPS connections in their transport configuration. Mixed
content downgrades the security of the entire communication channel, as any unencrypted
connection can be intercepted to steal credentials or modify traffic.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}


def _find_http_urls(config: dict, depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    hits: list[str] = []
    for k, v in config.items():
        if isinstance(v, str):
            try:
                if urlparse(v).scheme == "http" and "localhost" not in v and "127.0.0.1" not in v:
                    hits.append(f"'{k}' = '{v}'")
            except Exception:  # noqa: BLE001
                pass
        if isinstance(v, dict):
            hits.extend(_find_http_urls(v, depth + 1))
    return hits


class MixedContentCheck(BaseCheck):
    """Mixed Content Transport."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        # Only a concern when the primary transport is HTTPS
        is_https = snapshot.transport_url and snapshot.transport_url.startswith("https://")
        if not is_https:
            return []
        http_urls = _find_http_urls(snapshot.config_raw or {})
        if http_urls:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="mixed_content",
                    status_extended=(
                        f"Server '{snapshot.server_name}' mixes HTTPS with HTTP URLs in config: "
                        f"{'; '.join(http_urls[:3])}."
                    ),
                    evidence=f"HTTP URLs in HTTPS context: {http_urls[:3]}",
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
                resource_name="mixed_content",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not mix HTTP and HTTPS content."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
