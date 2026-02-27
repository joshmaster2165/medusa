"""AGENT-012: Agent Persistence Risk.

Checks for tools that persist state across sessions without session
control config (session expiry, clear_session, session_timeout, etc.).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.session import SESSION_TIMEOUT_KEYS

PERSISTENCE_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(save|store|persist|remember|write)[-_]?(session|memory|state|context|history)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(long[-_]?term|cross[-_]?session|persistent)[-_]?(memory|storage|state)", re.IGNORECASE
    ),
]


class AgentPersistenceRiskCheck(BaseCheck):
    """Agent Persistence Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_session_control = _walk_config_for_keys(snapshot.config_raw, SESSION_TIMEOUT_KEYS)

        persistence_tools: list[str] = []
        for tool in snapshot.tools:
            combined = f"{tool.get('name', '')} {tool.get('description', '')}"
            if any(p.search(combined) for p in PERSISTENCE_TOOL_PATTERNS):
                persistence_tools.append(tool.get("name", "<unnamed>"))

        if persistence_tools and not has_session_control:
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
                        f"Cross-session persistence tools detected "
                        f"({', '.join(persistence_tools[:5])}) with no session control config."
                    ),
                    evidence=f"persistence_tools={persistence_tools[:5]}",
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
                    status_extended="No uncontrolled agent persistence risk detected.",
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
