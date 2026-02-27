"""PRIV-023: Cross-Tenant Data Access.

Detects tools that accept tenant_id parameters without enforcement, enabling
cross-tenant data access in multi-tenant MCP deployments.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_TENANT_PARAMS = {
    "tenant_id",
    "tenantid",
    "org_id",
    "orgid",
    "organization_id",
    "workspace_id",
    "company_id",
    "account_id",
    "team_id",
}
_TENANT_ISOLATION_KEYS = {
    "tenant_isolation",
    "multi_tenant",
    "tenant_filter",
    "tenant_context",
    "tenant_scope",
    "row_level_security",
    "rls",
}


class CrossTenantAccessCheck(BaseCheck):
    """Detect tools with tenant_id params lacking isolation enforcement."""

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
        has_isolation = any(k in config_str for k in _TENANT_ISOLATION_KEYS)

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema") or {}
            properties = (
                input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
            )

            tenant_params = [p for p in properties if p.lower() in _TENANT_PARAMS]
            if not tenant_params:
                continue

            if has_isolation:
                continue

            # Check if tenant params have any constraint
            unconstrained = [
                p
                for p in tenant_params
                if isinstance(properties.get(p), dict)
                and not properties[p].get("enum")
                and not properties[p].get("const")
            ]
            if not unconstrained:
                continue

            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=tool_name,
                    status_extended=(
                        f"Tool '{tool_name}' accepts unconstrained tenant identifier(s) "
                        f"{unconstrained} without isolation enforcement, enabling "
                        f"cross-tenant data access."
                    ),
                    evidence=f"Unconstrained tenant params: {unconstrained}; no isolation config.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if not findings and snapshot.tools:
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
                    status_extended="No cross-tenant access risk detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
