"""AUTH008: Missing OAuth PKCE.

Detects OAuth 2.0 authorization flows that do not implement Proof Key for Code Exchange (PKCE).
Without PKCE, authorization codes are vulnerable to interception attacks where a malicious
application captures the code and exchanges it for an access token.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_OAUTH_KEYS = {"oauth", "oauth2", "oidc"}
_PKCE_KEYS = {"pkce", "code_challenge", "code_challenge_method", "code_verifier"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class MissingOauthPkceCheck(BaseCheck):
    """Missing OAuth PKCE."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_oauth = _walk_config(snapshot.config_raw or {}, _OAUTH_KEYS)
        if not has_oauth:
            return []
        has_pkce = _walk_config(snapshot.config_raw or {}, _PKCE_KEYS)
        if not has_pkce:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="oauth.pkce",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses OAuth without PKCE. "
                        f"Authorization codes can be intercepted and exchanged by an attacker."
                    ),
                    evidence="OAuth config present but no code_challenge/pkce key found",
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
                resource_name="oauth.pkce",
                status_extended=(
                    f"Server '{snapshot.server_name}' OAuth configuration includes PKCE."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
