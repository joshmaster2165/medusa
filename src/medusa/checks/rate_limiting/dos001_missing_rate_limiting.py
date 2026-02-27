"""DOS001: Missing Rate Limiting.

Detects MCP server configurations that lack rate limiting on tool invocations. Without rate
limits, an attacker or compromised LLM agent can invoke tools at an unlimited rate, overwhelming
the server and any downstream services the tools interact with.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import RATE_LIMIT_CONFIG_KEYS, RATE_LIMIT_ENV_VARS


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


def _config_check(
    snapshot: ServerSnapshot,
    meta: CheckMetadata,
    config_keys: set[str],
    env_vars: set[str],
    missing_msg: str,
    present_msg: str,
) -> list[Finding]:
    """Generic config-walk check: FAIL if keys absent, PASS if present."""
    found_config = False
    found_env = False

    if snapshot.config_raw:
        found_config = _walk_config_for_keys(snapshot.config_raw, config_keys)

    if snapshot.env and not found_config:
        for var in snapshot.env:
            if var.upper() in env_vars:
                found_env = True
                break

    found = found_config or found_env

    status = Status.PASS if found else Status.FAIL
    sources: list[str] = []
    if found_config:
        sources.append("config_raw")
    if found_env:
        sources.append("environment variables")

    status_extended = (
        present_msg.format(sources=", ".join(sources))
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
            evidence=(
                f"config_raw keys checked: {bool(snapshot.config_raw)}, "
                f"env vars checked: {len(snapshot.env)}"
            ),
            remediation=meta.remediation,
            owasp_mcp=meta.owasp_mcp,
        )
    ]


class MissingRateLimitingCheck(BaseCheck):
    """Missing Rate Limiting."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        return _config_check(
            snapshot,
            meta,
            config_keys=RATE_LIMIT_CONFIG_KEYS,
            env_vars=RATE_LIMIT_ENV_VARS,
            missing_msg=(
                "Server '{server}' has no rate limiting configuration. "
                "Unlimited tool invocations risk DoS."
            ),
            present_msg="Rate limiting configuration detected in: {sources}.",
        )
