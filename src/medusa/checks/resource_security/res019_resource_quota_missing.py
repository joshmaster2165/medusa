"""RES019: Missing Resource Quota.

Detects MCP servers that do not enforce quotas on resource creation, storage, or access
frequency per client. Without quotas, a single client can monopolize server resources, starving
other clients and causing denial of service through resource exhaustion.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.rate_limiting_patterns import RATE_LIMIT_CONFIG_KEYS, RESOURCE_LIMIT_KEYS

QUOTA_CONFIG_KEYS: set[str] = (
    RATE_LIMIT_CONFIG_KEYS
    | RESOURCE_LIMIT_KEYS
    | {
        "quota",
        "resource_quota",
        "access_quota",
        "per_client_limit",
        "per_user_limit",
        "client_quota",
        "user_quota",
        "max_requests_per_client",
        "quota_limit",
        "usage_limit",
    }
)


class ResourceQuotaMissingCheck(BaseCheck):
    """Missing Resource Quota."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        has_quota = _walk_config_for_keys(snapshot.config_raw, QUOTA_CONFIG_KEYS)

        if not has_quota:
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
                        f"Server exposes {len(snapshot.resources)} resource(s) but no "
                        f"per-client quota or access limits detected — DoS via resource "
                        f"exhaustion is possible."
                    ),
                    evidence="No quota keys found in config_raw.",
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
                    status_extended="Resource quota or access limit configuration detected.",
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
