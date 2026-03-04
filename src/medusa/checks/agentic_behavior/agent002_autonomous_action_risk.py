"""AGENT-002: Autonomous Action Risk.

For each tool classified as DESTRUCTIVE, PRIVILEGED, or EXFILTRATIVE,
checks whether the tool's inputSchema contains confirmation or rate-limit
parameters that act as safeguards against autonomous invocation.  Also
checks server config for auto-approve/auto-execute settings as a
secondary signal.  Emits a per-tool FAIL when no safeguards are found.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.agentic import (
    CONFIRMATION_SCHEMA_PARAMS,
    RATE_LIMIT_SCHEMA_PARAMS,
)

AUTO_APPROVE_KEYS: set[str] = {
    "auto_approve",
    "auto_execute",
    "auto_run",
    "auto_confirm",
    "autonomous",
    "no_confirm",
    "skip_confirmation",
    "headless",
    "unattended",
    "non_interactive",
}


class AutonomousActionRiskCheck(BaseCheck):
    """Autonomous Action Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Secondary signal: auto-approve config keys present
        has_auto_approve = _walk_config_for_keys(
            snapshot.config_raw, AUTO_APPROVE_KEYS
        )

        safeguard_params = CONFIRMATION_SCHEMA_PARAMS | RATE_LIMIT_SCHEMA_PARAMS
        risky_levels = (ToolRisk.DESTRUCTIVE, ToolRisk.PRIVILEGED, ToolRisk.EXFILTRATIVE)

        for tool in snapshot.tools:
            risk = classify_tool_risk(tool)
            if risk not in risky_levels:
                continue

            tool_name: str = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}

            has_confirm = bool(param_names & CONFIRMATION_SCHEMA_PARAMS)
            has_rate_limit = bool(param_names & RATE_LIMIT_SCHEMA_PARAMS)

            if has_confirm or has_rate_limit:
                # Tool has schema-level safeguards -- safe
                continue

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
                        f"Tool '{tool_name}' ({risk.value}) has no confirmation "
                        f"or rate-limit parameters in its schema. It can be "
                        f"autonomously invoked without safeguards."
                    ),
                    evidence=(
                        f"risk={risk.value}, "
                        f"params={sorted(param_names)[:10]}, "
                        f"confirm_param=missing, "
                        f"rate_limit_param=missing, "
                        f"auto_approve_config={'present' if has_auto_approve else 'absent'}"
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
                        f"All high-risk tools have confirmation or rate-limit "
                        f"parameters, or no high-risk tools found across "
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
