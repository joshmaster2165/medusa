"""RES-015: Resource Subscription Abuse.

Checks if resource subscriptions have limits. Fails when resources are
exposed and subscriptions capability is present but no subscription
limit config is found.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.rate_limiting_patterns import RATE_LIMIT_CONFIG_KEYS

SUBSCRIPTION_LIMIT_KEYS = RATE_LIMIT_CONFIG_KEYS | {
    "max_subscriptions",
    "subscription_limit",
    "max_subscribers",
    "subscription_quota",
    "subscription_rate_limit",
}


class ResourceSubscriptionAbuseCheck(BaseCheck):
    """Resource Subscription Abuse."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        # Only relevant if subscriptions are exposed
        caps = snapshot.capabilities or {}
        has_subscriptions = (
            "subscriptions" in caps
            or "subscribe" in caps
            or any("subscri" in str(r.get("uri", "")).lower() for r in snapshot.resources)
        )

        if not has_subscriptions:
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
                    status_extended="No subscription capability detected — subscription abuse not"
                    "applicable.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        has_limit = _walk_config_for_keys(snapshot.config_raw, SUBSCRIPTION_LIMIT_KEYS)

        if not has_limit:
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
                        "Resource subscriptions are available but no subscription "
                        "limit or rate limiting config detected."
                    ),
                    evidence="No subscription limit keys in config_raw.",
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
                    status_extended="Resource subscription limits detected.",
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
