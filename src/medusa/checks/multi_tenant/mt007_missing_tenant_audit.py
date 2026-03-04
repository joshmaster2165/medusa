"""MT007: Missing Tenant-Specific Audit.

Detects MCP server tools related to audit/logging that lack tenant-scoping
parameters, meaning audit trails cannot attribute operations to specific
tenants and security incidents cannot be properly investigated.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.multi_tenant import (
    TENANT_AUDIT_KEYWORDS,
    TENANT_ID_PARAMS,
)

_TENANT_AUDIT_KEYS = {
    "tenant_audit",
    "tenant_audit_log",
    "per_tenant_audit",
    "tenant_activity_log",
    "tenant_event_log",
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


def _tool_matches_keywords(tool: dict, keywords: set[str]) -> bool:
    """Check if a tool's name or description contains any of the keywords."""
    name = tool.get("name", "").lower().replace("-", "_")
    description = tool.get("description", "").lower()
    combined = name + " " + description
    return any(kw in combined for kw in keywords)


class MissingTenantAuditCheck(BaseCheck):
    """Missing Tenant-Specific Audit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Secondary signal: config-level tenant audit logging
        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw,
            _TENANT_AUDIT_KEYS,
        )

        # Check if any audit-related tools exist at all
        has_any_audit_tool = any(
            _tool_matches_keywords(t, TENANT_AUDIT_KEYWORDS) for t in snapshot.tools
        )

        if not has_any_audit_tool and not has_config_mitigation:
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
                        f"Server '{snapshot.server_name}' has "
                        f"{len(snapshot.tools)} tools but none provide "
                        f"tenant-scoped audit or logging functionality."
                    ),
                    evidence=(f"total_tools={len(snapshot.tools)}, audit_tools=0"),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        # Check existing audit tools for tenant scoping
        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")

            # Only flag audit/logging-related tools
            if not _tool_matches_keywords(tool, TENANT_AUDIT_KEYWORDS):
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}
            has_tenant_param = bool(param_names & TENANT_ID_PARAMS)

            if not has_tenant_param and not has_config_mitigation:
                matched_keywords = [
                    kw
                    for kw in TENANT_AUDIT_KEYWORDS
                    if kw in (tool.get("name", "") + " " + tool.get("description", "")).lower()
                ]
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
                            f"Audit tool '{tool_name}' has no tenant-scoping "
                            f"parameter. Audit trails cannot attribute "
                            f"operations to specific tenants."
                        ),
                        evidence=(
                            f"audit_keywords={matched_keywords[:5]}, "
                            f"params={sorted(param_names)[:10]}, "
                            f"tenant_param=missing"
                        ),
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
                    status_extended=(
                        "All audit/logging tools have tenant-scoping "
                        "parameters, or tenant-specific audit logging is "
                        "configured at the server level."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
