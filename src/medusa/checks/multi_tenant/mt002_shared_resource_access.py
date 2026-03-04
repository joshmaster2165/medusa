"""MT002: Shared Resource Cross-Tenant Access.

Detects MCP server resources that lack tenant-scoped URIs and tools that lack
tenant-scoping parameters, enabling cross-tenant data access through shared
resources such as files, database connections, caches, and temporary storage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.multi_tenant import (
    TENANT_ID_PARAMS,
    TENANT_URI_TEMPLATES,
)

_SHARED_RESOURCE_KEYS = {
    "resource_access_control",
    "resource_scoping",
    "resource_policy",
    "resource_authorization",
    "access_control",
    "resource_acl",
    "tenant_resource_filter",
}

# Risk levels that represent data-access tools needing tenant isolation
_DATA_ACCESS_RISKS = {
    ToolRisk.READ_ONLY,
    ToolRisk.DESTRUCTIVE,
    ToolRisk.EXFILTRATIVE,
    ToolRisk.PRIVILEGED,
}


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
    """Recursively walk config dict looking for any of the given keys."""
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in keys:
                return True
            if _walk_config_for_keys(config[key], keys, _depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk_config_for_keys(item, keys, _depth + 1):
                return True
    return False


def _resource_has_tenant_uri(resource: dict) -> bool:
    """Check if a resource URI contains a tenant-scoping template variable."""
    uri = resource.get("uri", "")
    if not uri:
        # Also check uriTemplate for dynamic resources
        uri = resource.get("uriTemplate", "")
    return any(tmpl in uri for tmpl in TENANT_URI_TEMPLATES)


class SharedResourceAccessCheck(BaseCheck):
    """Shared Resource Cross-Tenant Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        has_tools_or_resources = bool(snapshot.tools) or bool(snapshot.resources)
        if not has_tools_or_resources:
            return findings

        # Secondary signal: config-level resource access control
        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw,
            _SHARED_RESOURCE_KEYS,
        )

        # Check resources for tenant-scoped URIs
        for resource in snapshot.resources:
            resource_name = resource.get("name", resource.get("uri", "<unnamed>"))
            uri = resource.get("uri", resource.get("uriTemplate", ""))

            if not _resource_has_tenant_uri(resource) and not has_config_mitigation:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=resource_name,
                        status_extended=(
                            f"Resource '{resource_name}' has no tenant-scoped "
                            f"URI. It may be accessible across tenant boundaries."
                        ),
                        evidence=(f"uri={uri!r}, tenant_template=missing"),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Check tools for tenant-scoping parameters
        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            risk = classify_tool_risk(tool)

            if risk not in _DATA_ACCESS_RISKS:
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}
            has_tenant_param = bool(param_names & TENANT_ID_PARAMS)

            if not has_tenant_param and not has_config_mitigation:
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
                            f"Tool '{tool_name}' ({risk.value}) has no "
                            f"tenant-scoping parameter. Shared resources "
                            f"accessed by this tool may leak across tenants."
                        ),
                        evidence=(
                            f"risk={risk.value}, "
                            f"params={sorted(param_names)[:10]}, "
                            f"tenant_param=missing"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and has_tools_or_resources:
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
                    status_extended=(
                        "All resources have tenant-scoped URIs and data-access "
                        "tools have tenant-scoping parameters, or resource "
                        "access control is configured at the server level."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
