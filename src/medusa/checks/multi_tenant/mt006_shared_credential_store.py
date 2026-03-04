"""MT006: Shared Credential Store.

Detects MCP server tools that handle credentials (keys, tokens, secrets) but
lack tenant-scoping parameters, meaning credentials from multiple tenants
may be stored in a shared, unpartitioned credential store.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.multi_tenant import (
    TENANT_CREDENTIAL_KEYWORDS,
    TENANT_ID_PARAMS,
)

_CRED_ISOLATION_KEYS = {
    "tenant_credentials",
    "per_tenant_secrets",
    "credential_isolation",
    "tenant_secret_store",
    "tenant_vault",
    "per_tenant_keys",
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


class SharedCredentialStoreCheck(BaseCheck):
    """Shared Credential Store."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Secondary signal: config-level credential isolation
        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw,
            _CRED_ISOLATION_KEYS,
        )

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            risk = classify_tool_risk(tool)

            # Only check tools with known risk classification
            if risk not in _DATA_ACCESS_RISKS:
                continue

            # Only flag credential-handling tools
            if not _tool_matches_keywords(tool, TENANT_CREDENTIAL_KEYWORDS):
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}
            has_tenant_param = bool(param_names & TENANT_ID_PARAMS)

            if not has_tenant_param and not has_config_mitigation:
                matched_keywords = [
                    kw
                    for kw in TENANT_CREDENTIAL_KEYWORDS
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
                            f"Credential tool '{tool_name}' has no tenant-scoping "
                            f"parameter. Credentials may be stored in a shared "
                            f"store without per-tenant isolation."
                        ),
                        evidence=(
                            f"risk={risk.value}, "
                            f"credential_keywords={matched_keywords[:5]}, "
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
                        "All credential-handling tools have tenant-scoping "
                        "parameters, or per-tenant credential isolation is "
                        "configured at the server level."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
