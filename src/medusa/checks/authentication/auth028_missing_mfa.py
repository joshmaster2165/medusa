"""AUTH028: Missing Multi-Factor Authentication.

Detects MCP server configurations without support for multi-factor authentication. MFA provides
an additional layer of security beyond passwords, significantly reducing the risk of credential-
based attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.authentication import MFA_CONFIG_KEYS

_HTTP_TRANSPORTS = {"http", "sse"}
_AUTH_KEYS = {"auth", "authentication", "login", "oauth", "oidc"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class MissingMfaCheck(BaseCheck):
    """Missing Multi-Factor Authentication."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_auth = _walk_config(snapshot.config_raw or {}, _AUTH_KEYS)
        if not has_auth:
            return []
        has_mfa = _walk_config(snapshot.config_raw or {}, MFA_CONFIG_KEYS)
        if not has_mfa:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="auth.mfa",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no multi-factor authentication "
                        f"configured. Single-factor authentication is susceptible to credential"
                        f"theft."
                    ),
                    evidence="No mfa/2fa/totp/otp configuration keys found",
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
                resource_name="auth.mfa",
                status_extended=(
                    f"Server '{snapshot.server_name}' has multi-factor authentication configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
