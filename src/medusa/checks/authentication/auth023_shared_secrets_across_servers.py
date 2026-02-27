"""AUTH023: Shared Secrets Across Servers.

Detects identical credentials or API keys used across multiple MCP servers. Sharing secrets
across servers means that a compromise of one server exposes all servers using the same
credential.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SECRET_KEYS = {
    "secret",
    "api_key",
    "apikey",
    "token",
    "password",
    "shared_secret",
    "signing_key",
    "jwt_secret",
}
# Known placeholder / default secrets that indicate shared usage
_KNOWN_DEFAULTS = {
    "secret",
    "password",
    "changeme",
    "default",
    "test",
    "admin",
    "123456",
    "letmein",
    "mysecret",
    "sharedsecret",
}


def _extract_secrets(config: dict, depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    secrets: list[str] = []
    for k, v in config.items():
        if k.lower() in _SECRET_KEYS and isinstance(v, str) and v:
            secrets.append(v)
        if isinstance(v, dict):
            secrets.extend(_extract_secrets(v, depth + 1))
    return secrets


class SharedSecretsAcrossServersCheck(BaseCheck):
    """Shared Secrets Across Servers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        secrets = _extract_secrets(snapshot.config_raw or {})
        default_secrets = [s for s in secrets if s.lower() in _KNOWN_DEFAULTS]
        if default_secrets:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="shared_secret",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses well-known default or shared "
                        f"secrets that may be reused across multiple servers."
                    ),
                    evidence=f"Default/shared secret value detected: '{default_secrets[0]}'",
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
                resource_name="shared_secret",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to use known"
                    f"shared/default secrets."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
