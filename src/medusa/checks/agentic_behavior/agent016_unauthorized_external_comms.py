"""AGENT-016: Unauthorized External Communications.

Checks tools for external communication capabilities (HTTP, webhook, email,
network send) without an allowlist config. Flags servers where outbound
comms can be made to arbitrary external endpoints.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

EXTERNAL_COMM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(send|post|push)[-_]?(http|request|webhook|email|message|notification)", re.IGNORECASE
    ),
    re.compile(r"(call|invoke)[-_]?(external|remote|api|endpoint|url)", re.IGNORECASE),
    re.compile(r"(http|https)[-_]?(get|post|put|delete|request)", re.IGNORECASE),
    re.compile(r"(webhook|callback|notify)[-_]?(url|endpoint|server)", re.IGNORECASE),
]

ALLOWLIST_CONFIG_KEYS: set[str] = {
    "allowlist",
    "whitelist",
    "allowed_hosts",
    "allowed_urls",
    "allowed_domains",
    "outbound_allowlist",
    "permitted_hosts",
}


class UnauthorizedExternalCommsCheck(BaseCheck):
    """Unauthorized External Communications."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_allowlist = _walk_config_for_keys(snapshot.config_raw, ALLOWLIST_CONFIG_KEYS)

        external_tools: list[str] = []
        for tool in snapshot.tools:
            combined = f"{tool.get('name', '')} {tool.get('description', '')}"
            if any(p.search(combined) for p in EXTERNAL_COMM_PATTERNS):
                external_tools.append(tool.get("name", "<unnamed>"))

        if external_tools and not has_allowlist:
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
                        f"Tool(s) with external communication capability found "
                        f"({', '.join(external_tools[:5])}) without an allowlist config."
                    ),
                    evidence=f"external_comm_tools={external_tools[:5]}",
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
                    status_extended="No uncontrolled external communication tools detected.",
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
