"""AGENT-004: Multi-Step Attack Chain Risk.

Classifies ALL tools by risk using classify_tool_risk() and identifies
dangerous chain combinations that could be exploited:
  - READ_ONLY + EXFILTRATIVE  = data theft chain
  - READ_ONLY + DESTRUCTIVE   = informed destruction
  - PRIVILEGED + EXFILTRATIVE = privilege-to-exfil chain

Emits a server-level FAIL for each dangerous chain found.  Falls back to
config chain-limit checks as a mitigating factor.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.agentic import AGENT_SAFETY_CONFIG_KEYS

CHAIN_LIMIT_KEYS: set[str] = AGENT_SAFETY_CONFIG_KEYS | {
    "max_tool_calls",
    "max_chain_length",
    "chain_limit",
    "tool_call_limit",
}

# Dangerous chain combinations: (category_a, category_b, chain_label)
_DANGEROUS_CHAINS: list[tuple[ToolRisk, ToolRisk, str]] = [
    (ToolRisk.READ_ONLY, ToolRisk.EXFILTRATIVE, "data theft chain"),
    (ToolRisk.READ_ONLY, ToolRisk.DESTRUCTIVE, "informed destruction"),
    (ToolRisk.PRIVILEGED, ToolRisk.EXFILTRATIVE, "privilege-to-exfil chain"),
]


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

        has_chain_limit = _walk_config_for_keys(
            snapshot.config_raw, CHAIN_LIMIT_KEYS
        )

        # Classify all tools and group by risk category
        risk_groups: dict[ToolRisk, list[str]] = {}
        for tool in snapshot.tools:
            risk = classify_tool_risk(tool)
            tool_name = tool.get("name", "<unnamed>")
            risk_groups.setdefault(risk, []).append(tool_name)

        # Check for each dangerous chain combination
        for cat_a, cat_b, chain_label in _DANGEROUS_CHAINS:
            tools_a = risk_groups.get(cat_a, [])
            tools_b = risk_groups.get(cat_b, [])

            if not tools_a or not tools_b:
                continue

            if has_chain_limit:
                # Config has chain-limit -- mitigated, skip
                continue

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
                        f"Dangerous {chain_label} detected: "
                        f"{cat_a.value} tools ({', '.join(tools_a[:3])}) "
                        f"can be chained with {cat_b.value} tools "
                        f"({', '.join(tools_b[:3])}) with no chain limit "
                        f"in configuration."
                    ),
                    evidence=(
                        f"chain_type={chain_label}, "
                        f"{cat_a.value}_tools={tools_a[:5]}, "
                        f"{cat_b.value}_tools={tools_b[:5]}, "
                        f"chain_limit_config=missing"
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
                        f"No dangerous tool chain combinations detected, or "
                        f"chain limits are configured across "
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
