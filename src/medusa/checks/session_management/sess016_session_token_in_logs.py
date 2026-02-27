"""SESS016: Session Token in Logs.

Detects MCP server configurations where session tokens or session identifiers are written to
application logs, access logs, or debug output. Logged session tokens can be harvested by anyone
with access to log files, log aggregation systems, or monitoring dashboards.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_LOG_TOKEN_KEYS = {
    "log_tokens",
    "log_session_id",
    "log_auth",
    "include_token_in_logs",
    "debug_tokens",
    "verbose_auth",
}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


def _has_token_in_log_format(config: dict, depth: int = 0) -> str | None:
    """Check if log format strings contain session/token fields."""
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in {"log_format", "access_log_format", "log_fields"} and isinstance(v, str):
            if any(t in v.lower() for t in ("session", "token", "auth", "cookie")):
                return f"Log format key '{k}' includes session/token fields"
        if isinstance(v, dict):
            result = _has_token_in_log_format(v, depth + 1)
            if result:
                return result
    return None


class SessionTokenInLogsCheck(BaseCheck):
    """Session Token in Logs."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_explicit = _walk_config(snapshot.config_raw or {}, _LOG_TOKEN_KEYS)
        log_format_evidence = _has_token_in_log_format(snapshot.config_raw or {})
        evidence = log_format_evidence or ("Explicit log_tokens config" if has_explicit else None)
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
                    resource_name="logging.session_token",
                    status_extended=(
                        f"Server '{snapshot.server_name}' may log session tokens. "
                        f"Anyone with log access can steal active sessions."
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
                resource_name="logging.session_token",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to log session tokens."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
