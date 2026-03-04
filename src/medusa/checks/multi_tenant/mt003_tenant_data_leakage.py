"""MT003: Tenant Data Leakage.

Detects MCP servers where data-access tools (READ_ONLY or EXFILTRATIVE) lack
tenant-scoping parameters, meaning query results, exported data, or read
operations could leak data belonging to one tenant to another.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.multi_tenant import TENANT_ID_PARAMS

_LEAKAGE_PREVENTION_KEYS = {
    "data_isolation",
    "tenant_data_filter",
    "row_level_security",
    "data_scoping",
    "tenant_filter",
    "rls",
    "data_boundary",
}

# Tools classified as data-reading or data-exporting are leakage vectors
_LEAKAGE_RISKS = {
    ToolRisk.READ_ONLY,
    ToolRisk.EXFILTRATIVE,
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


class TenantDataLeakageCheck(BaseCheck):
    """Tenant Data Leakage."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Secondary signal: config-level data isolation
        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw,
            _LEAKAGE_PREVENTION_KEYS,
        )

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            risk = classify_tool_risk(tool)

            # Only check data-reading and data-exporting tools
            if risk not in _LEAKAGE_RISKS:
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
                            f"tenant-scoping parameter. Query results or "
                            f"exported data could leak across tenant boundaries."
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
                        "All data-reading and data-exporting tools have "
                        "tenant-scoping parameters, or data isolation is "
                        "configured at the server level."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
