"""AGENT-004: Multi-Step Attack Chain Risk.

Checks if tools can be chained without limits by detecting the presence
of both read/fetch tools and write/send tools with no chaining limit
config. Fails when > threshold tools exist and no chain limit is set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.agentic import AGENT_SAFETY_CONFIG_KEYS

CHAIN_LIMIT_KEYS: set[str] = AGENT_SAFETY_CONFIG_KEYS | {
    "max_tool_calls",
    "max_chain_length",
    "chain_limit",
    "tool_call_limit",
}
MULTI_TOOL_THRESHOLD = 5


class MultiStepAttackChainCheck(BaseCheck):
    """Multi-Step Attack Chain Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        tool_count = len(snapshot.tools)
        has_limit = _walk_config_for_keys(snapshot.config_raw, CHAIN_LIMIT_KEYS)

        if tool_count > MULTI_TOOL_THRESHOLD and not has_limit:
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
                        f"Server exposes {tool_count} tools with no chain/call limit "
                        f"in configuration, enabling unbounded multi-step attack chains."
                    ),
                    evidence=f"tool_count={tool_count}, threshold={MULTI_TOOL_THRESHOLD}",
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
                        f"Tool count ({tool_count}) within threshold or chain limit configured."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
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
