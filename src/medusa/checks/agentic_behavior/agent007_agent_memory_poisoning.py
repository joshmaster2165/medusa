"""AGENT-007: Agent Memory Poisoning.

Checks for tools that write to persistent state (memory/storage write tools)
without protection config such as input validation or access control.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.authentication import AUTH_CONFIG_KEYS

MEMORY_WRITE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(write|store|save|update|set|put)[-_]?(memory|state|context|cache)", re.IGNORECASE
    ),
    re.compile(r"memory[-_]?(write|update|store|set)", re.IGNORECASE),
    re.compile(r"(persist|remember|memorize)", re.IGNORECASE),
]


class AgentMemoryPoisoningCheck(BaseCheck):
    """Agent Memory Poisoning."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_protection = _walk_config_for_keys(snapshot.config_raw, AUTH_CONFIG_KEYS)

        memory_tools: list[str] = []
        for tool in snapshot.tools:
            name: str = tool.get("name", "")
            desc: str = tool.get("description", "")
            combined = f"{name} {desc}"
            if any(p.search(combined) for p in MEMORY_WRITE_PATTERNS):
                memory_tools.append(tool.get("name", "<unnamed>"))

        if memory_tools and not has_protection:
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
                        f"Tool(s) with persistent state write capability "
                        f"({', '.join(memory_tools[:5])}) detected without access controls."
                    ),
                    evidence=f"memory_write_tools={memory_tools[:5]}",
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
                    status_extended="No unprotected memory-write tools detected.",
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
