"""CTX007: Cross-Conversation Context Contamination.

Detects MCP server implementations that allow data from one conversation session to leak into
another. Cross-conversation contamination violates session isolation and exposes user data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SESSION_ISOLATION_KEYS = {
    "session_isolation",
    "isolate_sessions",
    "per_session_context",
    "conversation_isolation",
    "context_isolation",
    "session_scoped",
    "session_boundary",
    "stateless",
    "no_shared_state",
}


def _walk(config: Any, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    if isinstance(config, dict):
        for k, v in config.items():
            if isinstance(k, str) and k.lower() in keys:
                return True
            if _walk(v, keys, depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk(item, keys, depth + 1):
                return True
    return False


class CrossConversationContaminationCheck(BaseCheck):
    """Cross-Conversation Context Contamination."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()

        found = _walk(snapshot.config_raw or {}, _SESSION_ISOLATION_KEYS)
        if found:
            status = Status.PASS
            msg = (
                f"Server '{snapshot.server_name}' has session-isolation configuration; "
                f"cross-conversation contamination risk is mitigated."
            )
        else:
            status = Status.FAIL
            msg = (
                f"Server '{snapshot.server_name}' has no session-isolation configuration. "
                f"Conversation context may bleed between sessions."
            )

        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=status,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=msg,
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
