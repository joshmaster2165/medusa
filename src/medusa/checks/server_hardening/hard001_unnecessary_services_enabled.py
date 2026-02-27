"""HARD001: Unnecessary Services Enabled.

Detects MCP servers that expose capabilities, endpoints, or protocol features beyond what is
required for their intended function. Each unnecessary service increases the attack surface and
provides additional vectors for exploitation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Capability names considered optional / potentially unnecessary
_OPTIONAL_CAPABILITIES = {"experimental", "logging", "prompts", "resources"}
# Threshold: if all three of tools+resources+prompts are active, flag it
_MULTI_CAPABILITY_THRESHOLD = 3


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
    """Recursively walk a config dict looking for any of the given keys."""
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


def _hardening_config_check(
    snapshot: ServerSnapshot,
    meta: CheckMetadata,
    bad_keys: set[str],
    bad_values: set[str] | None,
    missing_msg: str,
    present_msg: str,
    fail_on_present: bool = True,
) -> list[Finding]:
    """Config walk check: FAIL if key found (and value matches), PASS otherwise.

    If fail_on_present=False, logic is inverted (FAIL if key absent).
    """
    found = _walk_config_for_keys(snapshot.config_raw or {}, bad_keys)

    if fail_on_present:
        status = Status.FAIL if found else Status.PASS
        status_extended = (
            missing_msg.format(server=snapshot.server_name)
            if found
            else present_msg.format(server=snapshot.server_name)
        )
    else:
        status = Status.PASS if found else Status.FAIL
        status_extended = (
            present_msg.format(server=snapshot.server_name)
            if found
            else missing_msg.format(server=snapshot.server_name)
        )

    return [
        Finding(
            check_id=meta.check_id,
            check_title=meta.title,
            status=status,
            severity=meta.severity,
            server_name=snapshot.server_name,
            server_transport=snapshot.transport_type,
            resource_type="server",
            resource_name=snapshot.server_name,
            status_extended=status_extended,
            evidence=f"config_raw keys checked: {bool(snapshot.config_raw)}",
            remediation=meta.remediation,
            owasp_mcp=meta.owasp_mcp,
        )
    ]


class UnnecessaryServicesEnabledCheck(BaseCheck):
    """Unnecessary Services Enabled."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()

        # Count active capability types
        active: list[str] = []
        caps = snapshot.capabilities or {}
        if snapshot.tools:
            active.append("tools")
        if snapshot.resources:
            active.append("resources")
        if snapshot.prompts:
            active.append("prompts")
        for cap in caps:
            if cap in _OPTIONAL_CAPABILITIES and cap not in active:
                active.append(cap)

        if len(active) >= _MULTI_CAPABILITY_THRESHOLD:
            return [
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
                        f"Server '{snapshot.server_name}' exposes {len(active)} capability "
                        f"types ({', '.join(active)}). Disable unnecessary services to reduce "
                        f"attack surface."
                    ),
                    evidence=f"active_capabilities={active}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

        return [
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
                    f"Server '{snapshot.server_name}' exposes a minimal set of capabilities "
                    f"({', '.join(active) or 'none'})."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
