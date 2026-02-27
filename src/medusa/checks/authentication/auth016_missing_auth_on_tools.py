"""AUTH016: Missing Authentication on Sensitive Tools.

Detects MCP tools that perform sensitive operations (file access, database queries, network
requests, system commands) without requiring authentication. Unauthenticated access to dangerous
tools allows any client to perform privileged operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SENSITIVE_TOOL_NAMES = {
    "delete",
    "drop",
    "remove",
    "destroy",
    "wipe",
    "purge",
    "truncate",
    "exec",
    "execute",
    "run",
    "shell",
    "command",
    "cmd",
    "write",
    "upload",
    "create",
    "insert",
    "update",
    "modify",
    "admin",
    "root",
    "sudo",
    "privilege",
}
_AUTH_CONFIG_KEYS = {"auth", "authentication", "authorization", "require_auth", "protected"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


def _tool_is_sensitive(tool: dict) -> bool:
    name = tool.get("name", "").lower()
    return any(s in name for s in _SENSITIVE_TOOL_NAMES)


class MissingAuthOnToolsCheck(BaseCheck):
    """Missing Authentication on Sensitive Tools."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        sensitive_tools = [t for t in snapshot.tools if _tool_is_sensitive(t)]
        if not sensitive_tools:
            return []
        has_auth = _walk_config(snapshot.config_raw or {}, _AUTH_CONFIG_KEYS)
        if not has_auth:
            names = [t.get("name", "?") for t in sensitive_tools[:5]]
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=names[0],
                    status_extended=(
                        f"Server '{snapshot.server_name}' exposes sensitive tools "
                        f"({', '.join(names)}) without authentication configuration."
                    ),
                    evidence=f"Sensitive tools with no auth: {names}",
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
                resource_name="auth",
                status_extended=(
                    f"Server '{snapshot.server_name}' has authentication configured for tools."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
