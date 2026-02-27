"""INTG017: Missing Timestamp Verification.

Detects signed artifacts that lack timestamp verification. Without trusted timestamps,
signatures remain valid even after the signing key has been compromised or revoked.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_TARGET_KEYS: set[str] = {
    "timestamp",
    "ntp",
    "time_sync",
    "clock_skew",
    "time_verification",
    "trusted_timestamp",
}


def _walk_config(config: Any, keys: set[str], _depth: int = 0) -> bool:
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in keys:
                return True
            if _walk_config(config[key], keys, _depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk_config(item, keys, _depth + 1):
                return True
    return False


class TimestampVerificationMissingCheck(BaseCheck):
    """Timestamp Verification Missing."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.config_raw:
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
                    status_extended="No timestamp verification configuration detected.",
                    evidence="missing_keys=timestamp,ntp,time_sync",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        has_keys = _walk_config(snapshot.config_raw, _TARGET_KEYS)
        if not has_keys:
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
                    status_extended="No timestamp verification configuration detected.",
                    evidence="missing_keys=timestamp,ntp,time_sync",
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
                    status_extended="Timestamp verification configuration detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
