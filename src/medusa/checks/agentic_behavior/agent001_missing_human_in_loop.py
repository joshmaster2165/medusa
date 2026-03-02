"""AGENT-001: Missing Human-in-the-Loop.

Checks if tools with destructive or privileged risk profiles have a
corresponding confirmation/approval mechanism in config.  Uses semantic
tool-risk classification from name + description analysis rather than
simple keyword substring matching.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.agentic import CONFIRMATION_CONFIG_KEYS


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

        has_confirmation = _walk_config_for_keys(snapshot.config_raw, CONFIRMATION_CONFIG_KEYS)

        # Classify each tool's risk using semantic analysis
        high_risk_tools: list[tuple[str, ToolRisk]] = []
        for tool in snapshot.tools:
            risk = classify_tool_risk(tool)
            if risk in (ToolRisk.DESTRUCTIVE, ToolRisk.PRIVILEGED):
                tool_name = tool.get("name", "<unnamed>")
                high_risk_tools.append((tool_name, risk))

        if high_risk_tools and not has_confirmation:
            tool_names = [name for name, _ in high_risk_tools[:5]]
            risk_details = ", ".join(
                f"{name} ({risk.value})"
                for name, risk in high_risk_tools[:5]
            )
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
                        f"Server exposes {len(high_risk_tools)} high-risk tool(s) "
                        f"({', '.join(tool_names)}) without a confirmation "
                        f"mechanism in configuration."
                    ),
                    evidence=f"high_risk_tools=[{risk_details}]",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                        "No unguarded high-risk tools detected, or confirmation "
                        "mechanism is present in configuration."
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
