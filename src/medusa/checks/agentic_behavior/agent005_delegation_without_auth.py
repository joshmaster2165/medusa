"""AGENT-005: Delegation Without Authorization.

Checks for DELEGATION_KEYWORDS in tool descriptions without auth requirements
in config. Fails when delegation-style tools exist with no auth config.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.agentic import DELEGATION_KEYWORDS
from medusa.utils.patterns.authentication import AUTH_CONFIG_KEYS


class DelegationWithoutAuthCheck(BaseCheck):
    """Delegation Without Authorization."""

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

        delegation_tools: list[str] = []
        for tool in snapshot.tools:
            name: str = tool.get("name", "").lower()
            desc: str = tool.get("description", "").lower()
            combined = f"{name} {desc}"
            if any(kw in combined for kw in DELEGATION_KEYWORDS):
                delegation_tools.append(tool.get("name", "<unnamed>"))

        if delegation_tools and not has_auth:
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
                        f"Tool(s) with delegation keywords found "
                        f"({', '.join(delegation_tools[:5])}) but no auth config detected."
                    ),
                    evidence=f"delegation_tools={delegation_tools[:5]}",
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
                        "No unguarded delegation tools detected, or auth config is present."
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
