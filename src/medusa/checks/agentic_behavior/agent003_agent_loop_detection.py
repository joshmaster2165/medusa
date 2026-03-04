"""AGENT-003: Agent Loop Detection.

Checks each tool's inputSchema for recursion-enabling parameters (depth,
max_iterations, etc.) and verifies they have constraints (maximum or enum).
Also detects circular reference risk when a tool's description references
another tool by name.  Falls back to config-level safety key checks as a
secondary signal.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.agentic import AGENT_SAFETY_CONFIG_KEYS, RECURSION_PARAMS


class AgentLoopDetectionCheck(BaseCheck):
    """Agent Loop Detection."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_config_safety = _walk_config_for_keys(
            snapshot.config_raw, AGENT_SAFETY_CONFIG_KEYS
        )

        # Collect all tool names for cross-reference detection
        all_tool_names: set[str] = set()
        for tool in snapshot.tools:
            name = tool.get("name", "")
            if name:
                all_tool_names.add(name.lower())

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            # --- Check 1: Recursion params without constraints ---
            unconstrained_params: list[str] = []
            for param_key, param_def in properties.items():
                if param_key.lower() not in RECURSION_PARAMS:
                    continue
                # Check if the param has a maximum or enum constraint
                if not isinstance(param_def, dict):
                    unconstrained_params.append(param_key)
                    continue
                has_maximum = "maximum" in param_def
                has_enum = "enum" in param_def
                if not has_maximum and not has_enum:
                    unconstrained_params.append(param_key)

            if unconstrained_params and not has_config_safety:
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
                            f"Tool '{tool_name}' has recursion-enabling "
                            f"parameter(s) without constraints: "
                            f"{', '.join(unconstrained_params)}. "
                            f"No config-level safety limits detected."
                        ),
                        evidence=(
                            f"unconstrained_recursion_params="
                            f"{unconstrained_params}, "
                            f"config_safety=missing"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

            # --- Check 2: Circular reference risk ---
            description = tool.get("description", "").lower()
            referenced_tools: list[str] = []
            for other_name in all_tool_names:
                if other_name == tool_name.lower():
                    continue
                if other_name in description:
                    referenced_tools.append(other_name)

            if referenced_tools:
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
                            f"Tool '{tool_name}' references other tool(s) "
                            f"by name in its description: "
                            f"{', '.join(referenced_tools[:5])}. "
                            f"This creates circular invocation risk."
                        ),
                        evidence=(
                            f"referenced_tools={referenced_tools[:5]}, "
                            f"config_safety="
                            f"{'present' if has_config_safety else 'missing'}"
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
                        f"No unconstrained recursion parameters or circular "
                        f"references detected across {len(snapshot.tools)} "
                        f"tool(s)."
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
