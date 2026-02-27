"""SESS001: Missing Session Timeout.

Detects MCP server configurations that lack session timeout settings for client connections.
When sessions between LLM clients and MCP servers persist indefinitely, abandoned or forgotten
sessions remain active and exploitable. Tool invocations can continue on stale sessions long
after the user has disengaged.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.session import SESSION_TIMEOUT_KEYS

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


class MissingSessionTimeoutCheck(BaseCheck):
    """Missing Session Timeout."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_timeout = _walk_config(snapshot.config_raw or {}, SESSION_TIMEOUT_KEYS)
        if not has_timeout:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.timeout",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no session timeout configured. "
                        f"Abandoned sessions remain active indefinitely."
                    ),
                    evidence="No timeout/ttl/max_age/lifetime key found in session config",
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
                resource_name="session.timeout",
                status_extended=(
                    f"Server '{snapshot.server_name}' has session timeout configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
