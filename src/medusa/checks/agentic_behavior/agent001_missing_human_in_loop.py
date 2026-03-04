"""AGENT-001: Missing Human-in-the-Loop.

For each tool classified as DESTRUCTIVE or PRIVILEGED, checks whether the
tool's inputSchema contains a confirmation/approval parameter AND whether
the server config has a confirmation mechanism.  Emits a per-tool FAIL
when both layers are absent.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.agentic import (
    CONFIRMATION_CONFIG_KEYS,
    CONFIRMATION_SCHEMA_PARAMS,
)


class MissingHumanInLoopCheck(BaseCheck):
    """Missing Human-in-the-Loop."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_config_confirmation = _walk_config_for_keys(
            snapshot.config_raw, CONFIRMATION_CONFIG_KEYS
        )

        for tool in snapshot.tools:
            risk = classify_tool_risk(tool)
            if risk not in (ToolRisk.DESTRUCTIVE, ToolRisk.PRIVILEGED):
                continue

            tool_name: str = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}
            has_confirm_param = bool(param_names & CONFIRMATION_SCHEMA_PARAMS)

            if has_confirm_param:
                # Tool has its own confirmation parameter -- safe
                continue

            if has_config_confirmation:
                # No schema param, but server config has confirmation -- safe
                continue

            # Neither schema param nor config confirmation
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
                        f"Tool '{tool_name}' is classified as {risk.value.upper()} "
                        f"but has no confirmation or dry-run parameter in its "
                        f"schema, and no confirmation mechanism in server config."
                    ),
                    evidence=(
                        f"risk={risk.value}, "
                        f"params={sorted(param_names)[:10]}, "
                        f"confirm_param=missing, "
                        f"config_confirmation=missing"
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
                        f"All high-risk tools have confirmation parameters "
                        f"or server-level confirmation is configured "
                        f"across {len(snapshot.tools)} tool(s)."
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
