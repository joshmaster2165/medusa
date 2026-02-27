"""AUTH019: Token Scope Too Broad.

Detects authentication tokens with excessively broad permission scopes that grant access beyond
what is required for the token's intended use. Over-scoped tokens violate the principle of least
privilege and amplify the impact of token compromise.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SCOPE_KEYS = {"scope", "scopes", "permissions", "roles", "access"}
_BROAD_VALUES = {
    "*",
    "all",
    "admin",
    "root",
    "full_access",
    "write:all",
    "read:all",
    "full",
    "superuser",
    "unrestricted",
}


def _walk_config_for_scopes(config: dict, depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    hits: list[str] = []
    for k, v in config.items():
        if k.lower() in _SCOPE_KEYS:
            if isinstance(v, str):
                hits.extend(s.strip() for s in v.split())
            elif isinstance(v, list):
                hits.extend(str(s) for s in v)
        if isinstance(v, dict):
            hits.extend(_walk_config_for_scopes(v, depth + 1))
    return hits


class TokenScopeTooBroadCheck(BaseCheck):
    """Token Scope Too Broad."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        scopes = _walk_config_for_scopes(snapshot.config_raw or {})
        if not scopes:
            return []
        broad = [s for s in scopes if s.lower() in _BROAD_VALUES]
        if broad:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="token.scope",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses overly broad token scopes: "
                        f"{', '.join(sorted(set(broad)))}. Violates least privilege."
                    ),
                    evidence=f"Broad scopes detected: {sorted(set(broad))}",
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
                resource_name="token.scope",
                status_extended=(
                    f"Server '{snapshot.server_name}' token scopes appear appropriately restricted."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
