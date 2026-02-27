"""SAMP-007: Sampling Without Rate Limit.

Checks sampling config for rate limits. Fails when sampling is enabled
but no rate limiting config is detected.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.rate_limiting_patterns import RATE_LIMIT_CONFIG_KEYS

SAMPLING_RATE_KEYS = RATE_LIMIT_CONFIG_KEYS | {
    "sampling_rate_limit",
    "max_sampling_requests",
    "sampling_quota",
    "requests_per_session",
}


class SamplingWithoutRateLimitCheck(BaseCheck):
    """Sampling Without Rate Limit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if "sampling" not in snapshot.capabilities:
            return findings

        has_rate_limit = _walk_config_for_keys(snapshot.config_raw, SAMPLING_RATE_KEYS)

        if not has_rate_limit:
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
                        "Sampling is enabled but no rate limiting config detected — "
                        "sampling requests may exhaust LLM API quotas."
                    ),
                    evidence="sampling in capabilities; no rate limit config found.",
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
                    status_extended="Sampling rate limiting detected.",
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
