"""SESS012: Cross-Site Session Sharing.

Detects MCP server configurations where session tokens can be shared or reused across different
origins, domains, or MCP server instances. Cross-site session sharing violates the principle of
session isolation and allows a compromised server to leverage sessions established with a
different server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SESSION_KEYS = {"session", "session_store", "session_cookie"}
_ISOLATION_KEYS = {
    "domain",
    "cookie_domain",
    "session_domain",
    "origin",
    "allowed_origins",
    "samesite",
}


def _has_broad_domain(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in {"domain", "cookie_domain"} and isinstance(v, str):
            # A domain starting with a dot means it applies to all subdomains
            if v.startswith(".") or v == "*":
                return f"'{k}' = '{v}' (wildcard/subdomain scope)"
        if isinstance(v, dict):
            result = _has_broad_domain(v, depth + 1)
            if result:
                return result
    return None


class CrossSiteSessionSharingCheck(BaseCheck):
    """Cross-Site Session Sharing."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence = _has_broad_domain(snapshot.config_raw or {})
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
                    resource_name="session.domain",
                    status_extended=(
                        f"Server '{snapshot.server_name}' session cookie has a broad domain scope "
                        f"enabling cross-site session sharing."
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
                resource_name="session.domain",
                status_extended=(
                    f"Server '{snapshot.server_name}' session domain scope appears"
                    f"appropriately restricted."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
