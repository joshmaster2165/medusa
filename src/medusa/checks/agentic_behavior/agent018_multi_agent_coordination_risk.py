"""AGENT-018: Multi-Agent Coordination Risk.

Checks for agent-to-agent communication tools without auth config.
Flags servers exposing inter-agent messaging, orchestration, or
sub-agent spawning without authentication requirements.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.authentication import AUTH_CONFIG_KEYS

MULTI_AGENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(send|post|message)[-_]?(agent|bot|assistant|worker)", re.IGNORECASE),
    re.compile(r"(spawn|create|start|launch)[-_]?(agent|sub[-_]?agent|worker|bot)", re.IGNORECASE),
    re.compile(r"agent[-_]?(communicate|coordinate|message|call|invoke)", re.IGNORECASE),
    re.compile(r"(orchestrat|delegat|dispatch)[-_]?(agent|task|request)", re.IGNORECASE),
]


class MultiAgentCoordinationRiskCheck(BaseCheck):
    """Multi-Agent Coordination Risk."""

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

        coord_tools: list[str] = []
        for tool in snapshot.tools:
            combined = f"{tool.get('name', '')} {tool.get('description', '')}"
            if any(p.search(combined) for p in MULTI_AGENT_PATTERNS):
                coord_tools.append(tool.get("name", "<unnamed>"))

        if coord_tools and not has_auth:
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
                        f"Multi-agent coordination tool(s) found "
                        f"({', '.join(coord_tools[:5])}) without auth config."
                    ),
                    evidence=f"coordination_tools={coord_tools[:5]}",
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
                    status_extended="No unguarded multi-agent coordination tools detected.",
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
