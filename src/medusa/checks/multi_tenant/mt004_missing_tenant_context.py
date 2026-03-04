"""MT004: Missing Tenant Context Validation.

Detects MCP server tools whose descriptions suggest multi-tenant usage but
whose input schemas lack tenant-scoping parameters, allowing clients to
operate outside their authorized tenant scope.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.multi_tenant import TENANT_ID_PARAMS

_CONTEXT_VALIDATION_KEYS = {
    "tenant_context_validation",
    "tenant_verification",
    "tenant_claim",
    "tenant_assertion",
    "validate_tenant",
    "tenant_auth",
    "tenant_token_validation",
}

# Keywords in tool descriptions that suggest multi-tenant usage
_MULTI_TENANT_DESCRIPTION_KEYWORDS = {
    "tenant", "workspace", "organization", "org",
    "multi-tenant", "multitenant", "customer",
    "account", "namespace", "team", "company",
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


def _description_suggests_multi_tenant(tool: dict) -> bool:
    """Check if a tool's description mentions multi-tenant concepts."""
    description = tool.get("description", "").lower()
    if not description:
        return False
    desc_tokens = set(description.replace("-", " ").split())
    return bool(desc_tokens & _MULTI_TENANT_DESCRIPTION_KEYWORDS)


class MissingTenantContextCheck(BaseCheck):
    """Missing Tenant Context Validation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw, _CONTEXT_VALIDATION_KEYS,
        )

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")

            if not _description_suggests_multi_tenant(tool):
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}
            has_tenant = bool(param_names & TENANT_ID_PARAMS)

            if not has_tenant and not has_config_mitigation:
                findings.append(Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=tool_name,
                    status_extended=(
                        f"Tool '{tool_name}' description suggests multi-tenant "
                        f"usage but its schema has no tenant-scoping parameter. "
                        f"Clients may operate outside their authorized tenant scope."
                    ),
                    evidence=(
                        f"params={sorted(param_names)[:10]}, "
                        f"tenant_param=missing, "
                        f"description_mentions_tenant=true"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                ))

        if not findings and snapshot.tools:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    "Tools with multi-tenant descriptions have tenant-scoping "
                    "parameters, or tenant context validation is configured "
                    "at the server level."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))

        return findings
