"""TS016: Missing Content Security Policy.

Detects MCP server HTTP responses without Content-Security-Policy headers. CSP headers prevent
cross-site scripting, clickjacking, and other code injection attacks by restricting the sources
from which content can be loaded.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.transport import CSP_CONFIG_KEYS

_HTTP_TRANSPORTS = {"http", "sse"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        # Normalise key: lower-case and replace hyphens with underscores so that
        # HTTP header names like "Content-Security-Policy" match the config key
        # "content_security_policy".
        normalised = k.lower().replace("-", "_")
        if normalised in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class MissingContentSecurityPolicyCheck(BaseCheck):
    """Missing Content Security Policy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_csp = _walk_config(snapshot.config_raw or {}, CSP_CONFIG_KEYS)
        if not has_csp:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="csp",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no Content-Security-Policy"
                        f"configured. "
                        f"XSS and code injection attacks are not mitigated."
                    ),
                    evidence="No csp/content_security_policy/script_src configuration found",
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
                resource_name="csp",
                status_extended=(
                    f"Server '{snapshot.server_name}' has Content-Security-Policy configured."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
