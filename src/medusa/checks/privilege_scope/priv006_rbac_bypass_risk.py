"""PRIV-006: RBAC Bypass Risk.

Checks server configuration for role-based access control (RBAC) or
authorization settings. Absence indicates no role enforcement on tool access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_RBAC_KEYS = {
    "rbac",
    "roles",
    "role",
    "authorization",
    "authz",
    "permissions",
    "acl",
    "access_control",
    "policies",
    "policy",
    "scopes",
    "role_based",
    "role_mapping",
    "claims",
}


class RbacBypassRiskCheck(BaseCheck):
    """Check for absence of RBAC/authorization configuration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        config_str = str(snapshot.config_raw).lower() if snapshot.config_raw else ""
        args_str = " ".join(snapshot.args).lower()
        combined = f"{config_str} {args_str}"

        has_rbac = any(k in combined for k in _RBAC_KEYS)

        if not has_rbac:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        "No RBAC or authorization configuration detected. "
                        "Any authenticated user may invoke any tool regardless "
                        "of role or sensitivity of the operation."
                    ),
                    evidence="No rbac/roles/authorization/acl keys found in config.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended="RBAC/authorization configuration detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
