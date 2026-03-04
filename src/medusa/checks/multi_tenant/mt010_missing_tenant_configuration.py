"""MT010: Missing Tenant Configuration Isolation.

Detects MCP server tools related to configuration management (settings,
feature flags, policies) that lack tenant-scoping parameters, meaning
configuration changes by one tenant could affect other tenants.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.multi_tenant import (
    TENANT_CONFIG_KEYWORDS,
    TENANT_ID_PARAMS,
)

_TENANT_CONFIG_KEYS = {
    "tenant_config",
    "per_tenant_config",
    "tenant_settings",
    "tenant_feature_flags",
    "tenant_config_isolation",
}

# Risk levels for tools that should not be UNKNOWN
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


def _tool_matches_keywords(tool: dict, keywords: set[str]) -> bool:
    """Check if a tool's name or description contains any of the keywords."""
    name = tool.get("name", "").lower().replace("-", "_")
    description = tool.get("description", "").lower()
    combined = name + " " + description
    return any(kw in combined for kw in keywords)


class MissingTenantConfigurationCheck(BaseCheck):
    """Missing Tenant Configuration Isolation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Secondary signal: config-level tenant configuration isolation
        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw, _TENANT_CONFIG_KEYS,
        )

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            risk = classify_tool_risk(tool)

            # Only check tools with known risk classification
            if risk not in _DATA_ACCESS_RISKS:
                continue

            # Only flag config-management tools
            if not _tool_matches_keywords(tool, TENANT_CONFIG_KEYWORDS):
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}
            has_tenant_param = bool(param_names & TENANT_ID_PARAMS)

            if not has_tenant_param and not has_config_mitigation:
                matched_keywords = [
                    kw for kw in TENANT_CONFIG_KEYWORDS
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
                            f"Config tool '{tool_name}' has no tenant-scoping "
                            f"parameter. Configuration changes may bleed "
                            f"across tenant boundaries."
                        ),
                        evidence=(
                            f"risk={risk.value}, "
                            f"config_keywords={matched_keywords[:5]}, "
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
                        "All configuration-management tools have tenant-scoping "
                        "parameters, or tenant configuration isolation is "
                        "configured at the server level."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
