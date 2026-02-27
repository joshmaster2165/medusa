"""SESS003: Weak Session ID Entropy.

Detects MCP server session identifiers generated with insufficient randomness or entropy. Weak
session IDs that use predictable patterns, sequential numbers, or low-entropy random sources can
be guessed or brute-forced by attackers to hijack active LLM client connections.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_SECRET_KEYS = {"session_secret", "secret", "session_key", "cookie_secret"}
_MIN_SECRET_LENGTH = 32
_WEAK_SECRETS = {"secret", "password", "changeme", "session", "mysecret", "test"}


def _extract_session_secrets(config: dict, depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    secrets: list[str] = []
    for k, v in config.items():
        if k.lower() in _SESSION_SECRET_KEYS and isinstance(v, str) and v:
            secrets.append(v)
        if isinstance(v, dict):
            secrets.extend(_extract_session_secrets(v, depth + 1))
    return secrets


class WeakSessionIdEntropyCheck(BaseCheck):
    """Weak Session ID Entropy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        secrets = _extract_session_secrets(snapshot.config_raw or {})
        # Also check env vars
        for k, v in snapshot.env.items():
            if k.upper() in {"SESSION_SECRET", "COOKIE_SECRET"} and v:
                secrets.append(v)
        weak = [s for s in secrets if len(s) < _MIN_SECRET_LENGTH or s.lower() in _WEAK_SECRETS]
        if weak:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="session.secret",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses a weak session secret "
                        f"(too short or known default). Session IDs can be brute-forced."
                    ),
                    evidence=f"Weak session secret: '{weak[0][:8]}...' (length {len(weak[0])})",
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
                resource_name="session.secret",
                status_extended=(
                    f"Server '{snapshot.server_name}' session secret entropy appears adequate."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
