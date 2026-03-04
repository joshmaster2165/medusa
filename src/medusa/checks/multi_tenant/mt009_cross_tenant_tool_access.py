"""MT009: Cross-Tenant Tool Access.

Detects MCP servers where tools could allow cross-tenant access by:
1. Accepting tool_name/function_name parameters that enable meta-tool dispatch
2. Having DESTRUCTIVE or PRIVILEGED tools without tenant-scoping

In servers with 5+ tools, the ability to invoke arbitrary tools by name
combined with missing tenant isolation is especially dangerous.
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
    TOOL_DISPATCH_PARAMS,
)

_TOOL_ACCESS_KEYS = {
    "tool_access_policy",
    "tenant_tool_scope",
    "tool_authorization",
    "tool_visibility",
    "per_tenant_tools",
    "tenant_tool_filter",
}

# Powerful tools that need tenant scoping
_POWERFUL_RISKS = {
    ToolRisk.DESTRUCTIVE,
    ToolRisk.PRIVILEGED,
}

# All data-access risks
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


class CrossTenantToolAccessCheck(BaseCheck):
    """Cross-Tenant Tool Access."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Secondary signal: config-level tool access policy
        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw,
            _TOOL_ACCESS_KEYS,
        )

        has_many_tools = len(snapshot.tools) >= 5

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            risk = classify_tool_risk(tool)

            # Only check tools with known risk classification
            if risk not in _DATA_ACCESS_RISKS:
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}

            has_tenant_param = bool(param_names & TENANT_ID_PARAMS)
            has_dispatch_param = bool(param_names & TOOL_DISPATCH_PARAMS)

            # Check 1: Tool has dispatch params (can invoke other tools by name)
            if has_dispatch_param and not has_tenant_param and not has_config_mitigation:
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
                            f"Tool '{tool_name}' accepts tool dispatch parameters "
                            f"({sorted(param_names & TOOL_DISPATCH_PARAMS)}) "
                            f"without tenant scoping. This could allow one tenant "
                            f"to invoke tools registered by another tenant."
                        ),
                        evidence=(
                            f"risk={risk.value}, "
                            f"dispatch_params={sorted(param_names & TOOL_DISPATCH_PARAMS)}, "
                            f"tenant_param=missing, "
                            f"total_tools={len(snapshot.tools)}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
            # Check 2: Powerful tool without tenant scoping in a server with many tools
            elif (
                risk in _POWERFUL_RISKS
                and has_many_tools
                and not has_tenant_param
                and not has_config_mitigation
            ):
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
                            f"Tool '{tool_name}' ({risk.value}) has no tenant-scoping "
                            f"parameter in a server with {len(snapshot.tools)} tools. "
                            f"Cross-tenant tool access may enable unauthorized operations."
                        ),
                        evidence=(
                            f"risk={risk.value}, "
                            f"params={sorted(param_names)[:10]}, "
                            f"tenant_param=missing, "
                            f"total_tools={len(snapshot.tools)}"
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
                        "No cross-tenant tool access risks detected. Powerful "
                        "tools have tenant-scoping parameters, or tool access "
                        "policies are configured at the server level."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
