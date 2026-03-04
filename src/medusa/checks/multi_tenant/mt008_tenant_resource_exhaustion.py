"""MT008: Tenant Resource Exhaustion.

Detects MCP server tools classified as PRIVILEGED or with resource-intensive
indicators that lack both tenant-scoping and resource-limit parameters,
allowing a single tenant to monopolize shared server resources.
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
    TENANT_LIMIT_PARAMS,
    TENANT_RESOURCE_KEYWORDS,
)

_TENANT_QUOTA_KEYS = {
    "tenant_quota",
    "per_tenant_limit",
    "tenant_resource_limit",
    "tenant_rate_limit",
    "tenant_throttle",
    "tenant_cpu_limit",
    "tenant_memory_limit",
}

# Tools that are privileged or resource-intensive need quota controls
_RESOURCE_RISKS = {
    ToolRisk.PRIVILEGED,
    ToolRisk.DESTRUCTIVE,
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


def _is_resource_intensive(tool: dict) -> bool:
    """Check if a tool is resource-intensive based on name/description."""
    return _tool_matches_keywords(tool, TENANT_RESOURCE_KEYWORDS)


class TenantResourceExhaustionCheck(BaseCheck):
    """Tenant Resource Exhaustion."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Secondary signal: config-level tenant quotas
        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw, _TENANT_QUOTA_KEYS,
        )

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            risk = classify_tool_risk(tool)

            # Check privileged/destructive tools and resource-intensive tools
            is_risky = risk in _RESOURCE_RISKS
            is_intensive = _is_resource_intensive(tool)

            if not is_risky and not is_intensive:
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}

            has_tenant_param = bool(param_names & TENANT_ID_PARAMS)
            has_limit_param = bool(param_names & TENANT_LIMIT_PARAMS)

            # Flag if missing both tenant scoping AND limit parameters
            if not has_tenant_param and not has_limit_param and not has_config_mitigation:
                reason = "privileged" if is_risky else "resource-intensive"
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
                            f"Tool '{tool_name}' ({reason}) has no tenant-scoping "
                            f"or resource-limit parameters. A single tenant could "
                            f"monopolize server resources."
                        ),
                        evidence=(
                            f"risk={risk.value}, "
                            f"resource_intensive={is_intensive}, "
                            f"params={sorted(param_names)[:10]}, "
                            f"tenant_param=missing, limit_param=missing"
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
                        "All privileged and resource-intensive tools have "
                        "tenant-scoping or resource-limit parameters, or "
                        "per-tenant quotas are configured at the server level."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
