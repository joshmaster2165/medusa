"""AGENT-002: Autonomous Action Risk.

Checks configuration for auto-approve or auto-execute settings that
allow an agent to take actions without user intervention.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

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

        found_keys = _find_matching_keys(snapshot.config_raw, AUTO_APPROVE_KEYS)

        if found_keys:
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
                        f"Configuration contains autonomous execution settings: "
                        f"{', '.join(sorted(found_keys)[:5])}. "
                        f"Agent can take actions without user approval."
                    ),
                    evidence=f"auto_approve_keys={sorted(found_keys)[:5]}",
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
                    status_extended="No autonomous execution configuration detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings


def _find_matching_keys(config: Any, keys: set[str], _depth: int = 0) -> set[str]:
    """Recursively find all matching keys in config dict."""
    found: set[str] = set()
    if _depth > 10:
        return found
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in keys:
                found.add(key.lower())
            found |= _find_matching_keys(config[key], keys, _depth + 1)
    elif isinstance(config, list):
        for item in config:
            found |= _find_matching_keys(item, keys, _depth + 1)
    return found
