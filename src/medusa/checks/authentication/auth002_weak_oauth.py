"""AUTH-002: Weak OAuth Configuration.

Identifies OAuth configurations that are missing PKCE, use overly broad
scopes, or rely on insecure grant types such as the implicit flow.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}

# Scopes considered overly broad or dangerous.
_BROAD_SCOPES = {"*", "all", "admin", "root", "full_access", "write:all", "read:all"}

# Insecure grant types.
_INSECURE_GRANTS = {"implicit", "password", "client_credentials"}


def _find_oauth_config(config: dict | None) -> dict | None:
    """Extract the OAuth configuration block from the config dict."""
    if not config:
        return None

    # Direct top-level key.
    for key in ("oauth", "OAuth", "oauth2", "auth"):
        if key in config and isinstance(config[key], dict):
            return config[key]

    # Nested under server or transport config.
    for top_key in config:
        val = config[top_key]
        if isinstance(val, dict):
            for key in ("oauth", "OAuth", "oauth2", "auth"):
                if key in val and isinstance(val[key], dict):
                    return val[key]

    return None


class WeakOAuthCheck(BaseCheck):
    """Check for weak or misconfigured OAuth settings."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Only applicable to HTTP-based transports.
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []

        oauth_config = _find_oauth_config(snapshot.config_raw)

        # If there is no OAuth config at all on an HTTP transport, AUTH-001
        # already covers the "no auth" case. Skip to avoid duplicate findings.
        if oauth_config is None:
            return []

        # --- Check 1: Missing PKCE ---
        pkce_value = (
            oauth_config.get("code_challenge_method")
            or oauth_config.get("pkce")
            or oauth_config.get("codeChallengeMethod")
        )
        if not pkce_value or str(pkce_value).upper() not in ("S256", "TRUE", "ENABLED"):
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="oauth.code_challenge_method",
                    status_extended=(
                        f"Server '{snapshot.server_name}' OAuth configuration is "
                        f"missing PKCE (Proof Key for Code Exchange). Without PKCE, "
                        f"authorization codes can be intercepted and exchanged by "
                        f"an attacker."
                    ),
                    evidence=f"code_challenge_method = {pkce_value!r}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        # --- Check 2: Overly broad scopes ---
        scopes_raw = oauth_config.get("scopes") or oauth_config.get("scope") or ""
        if isinstance(scopes_raw, str):
            scopes = {s.strip().lower() for s in scopes_raw.split() if s.strip()}
        elif isinstance(scopes_raw, list):
            scopes = {str(s).strip().lower() for s in scopes_raw}
        else:
            scopes = set()

        broad_found = scopes & _BROAD_SCOPES
        if broad_found:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="oauth.scopes",
                    status_extended=(
                        f"Server '{snapshot.server_name}' OAuth configuration uses "
                        f"overly broad scopes: {', '.join(sorted(broad_found))}. "
                        f"This violates the principle of least privilege."
                    ),
                    evidence=f"scopes = {scopes_raw!r}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        # --- Check 3: Insecure grant type ---
        grant_type = (
            oauth_config.get("grant_type")
            or oauth_config.get("grantType")
            or oauth_config.get("response_type")
            or ""
        )
        if isinstance(grant_type, str) and grant_type.lower() in _INSECURE_GRANTS:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="oauth.grant_type",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses the insecure "
                        f"'{grant_type}' grant type. The MCP specification "
                        f"recommends the authorization code flow with PKCE."
                    ),
                    evidence=f"grant_type = {grant_type!r}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        # If no weaknesses were found, issue a PASS.
        if not findings:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="oauth",
                    status_extended=(
                        f"Server '{snapshot.server_name}' OAuth configuration "
                        f"appears properly configured with PKCE and narrow scopes."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
