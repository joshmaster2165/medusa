"""AGENT-005: Delegation Without Authorization.

For each tool whose name or description matches delegation keywords,
checks whether the tool's inputSchema contains authentication parameters
(token, credential, api_key, etc.).  Falls back to server config auth
keys as a secondary signal.  Emits a per-tool FAIL when neither layer
provides auth.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.agentic import AUTH_SCHEMA_PARAMS, DELEGATION_KEYWORDS
from medusa.utils.patterns.authentication import AUTH_CONFIG_KEYS


class DelegationWithoutAuthCheck(BaseCheck):
    """Delegation Without Authorization."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_config_auth = _walk_config_for_keys(
            snapshot.config_raw, AUTH_CONFIG_KEYS
        )

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            name_lower: str = tool_name.lower()
            desc_lower: str = tool.get("description", "").lower()
            combined = f"{name_lower} {desc_lower}"

            # Identify which delegation keywords matched
            matched_keywords = [kw for kw in DELEGATION_KEYWORDS if kw in combined]
            if not matched_keywords:
                continue

            # Check tool schema for auth parameters
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}
            has_auth_param = bool(param_names & AUTH_SCHEMA_PARAMS)

            if has_auth_param:
                # Tool has auth parameters in schema -- safe
                continue

            if has_config_auth:
                # No schema auth param, but server config has auth -- safe
                continue

            # Neither schema auth param nor config auth
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
                        f"Tool '{tool_name}' matches delegation keywords "
                        f"({', '.join(matched_keywords[:3])}) but has no "
                        f"auth parameters in its schema and no auth config "
                        f"at the server level."
                    ),
                    evidence=(
                        f"delegation_keywords={matched_keywords[:5]}, "
                        f"params={sorted(param_names)[:10]}, "
                        f"auth_param=missing, "
                        f"config_auth=missing"
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
                        f"All delegation tools have auth parameters or "
                        f"server-level auth config is present across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
    """Recursively walk config looking for any matching key."""
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
