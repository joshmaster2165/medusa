"""AUTH011: Hardcoded Credentials in Config.

Detects username and password pairs, API keys, and other credentials hardcoded directly in MCP
server configuration files or source code. Hardcoded credentials cannot be rotated without code
changes and are trivially extracted from the codebase.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_CRED_KEYS = {"password", "passwd", "pwd", "secret", "api_key", "apikey", "private_key"}
_USER_KEYS = {"username", "user", "login", "email"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    hits: list[str] = []
    for k, v in config.items():
        if k.lower() in keys and isinstance(v, str) and v and not v.startswith("${"):
            hits.append(f"'{k}' = '{v[:8]}...'")
        if isinstance(v, dict):
            hits.extend(_walk_config(v, keys, depth + 1))
    return hits


class HardcodedCredentialsCheck(BaseCheck):
    """Hardcoded Credentials in Config."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        cred_hits = _walk_config(snapshot.config_raw or {}, _CRED_KEYS)
        user_hits = _walk_config(snapshot.config_raw or {}, _USER_KEYS)
        # Flag if we have either passwords/secrets OR a username+password combo

        if cred_hits or user_hits:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="credentials",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has hardcoded credentials in config. "
                        f"Use environment variables or a secrets manager instead."
                    ),
                    evidence=f"Hardcoded credential keys: {', '.join(cred_hits[:3])}",
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
                resource_name="credentials",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to have hardcodedcredentials."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
