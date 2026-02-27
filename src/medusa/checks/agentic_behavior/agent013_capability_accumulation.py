"""AGENT-013: Capability Accumulation.

Checks if the agent can progressively gain more tool access. Flags
servers where tools include capability-granting patterns (grant, elevate,
add_permission, etc.) without access control configuration.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.authentication import AUTH_CONFIG_KEYS
from medusa.utils.patterns.injection import CAPABILITY_ESCALATION_KEYWORDS

CAPABILITY_GRANT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(grant|add|assign|give)[-_]?(permission|access|role|capability|privilege)", re.IGNORECASE
    ),
    re.compile(r"(elevate|escalate|upgrade)[-_]?(privilege|permission|role|access)", re.IGNORECASE),
    re.compile(
        r"(request|acquire|obtain)[-_]?(new|additional|more)[-_]?(tool|capability|access)",
        re.IGNORECASE,
    ),
]


class CapabilityAccumulationCheck(BaseCheck):
    """Capability Accumulation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_auth = _walk_config_for_keys(snapshot.config_raw, AUTH_CONFIG_KEYS)

        cap_tools: list[str] = []
        for tool in snapshot.tools:
            name: str = tool.get("name", "").lower()
            desc: str = tool.get("description", "").lower()
            combined = f"{name} {desc}"
            has_kw = any(kw in combined for kw in CAPABILITY_ESCALATION_KEYWORDS)
            has_pat = any(p.search(combined) for p in CAPABILITY_GRANT_PATTERNS)
            if has_kw or has_pat:
                cap_tools.append(tool.get("name", "<unnamed>"))

        if cap_tools and not has_auth:
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
                        f"Tool(s) enabling capability accumulation found "
                        f"({', '.join(cap_tools[:5])}) without access control config."
                    ),
                    evidence=f"capability_tools={cap_tools[:5]}",
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
                    status_extended="No uncontrolled capability accumulation paths detected.",
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
