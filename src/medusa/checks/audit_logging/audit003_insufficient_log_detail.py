"""AUDIT003: Insufficient Log Detail.

Detects MCP server logging configurations that lack essential detail such as caller identity,
tool invocation parameters, timestamps, or request correlation IDs. Incomplete logs hinder
security investigations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import LOGGING_CONFIG_KEYS

_LOG_DETAIL_KEYS: set[str] = {
    "caller",
    "caller_id",
    "user_id",
    "request_id",
    "correlation_id",
    "trace_id",
    "span_id",
    "timestamp",
    "params",
    "parameters",
    "structured",
    "structured_logging",
    "json_logging",
    "log_format",
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


class InsufficientLogDetailCheck(BaseCheck):
    """Insufficient Log Detail."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        has_logging = (
            _walk_config(snapshot.config_raw, LOGGING_CONFIG_KEYS) if snapshot.config_raw else False
        )
        if not has_logging:
            return findings  # No logging config at all — audit001 handles that

        has_detail = _walk_config(snapshot.config_raw, _LOG_DETAIL_KEYS)

        if not has_detail:
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
                        "Logging config lacks structured detail keys "
                        "(caller, correlation_id, etc.)."
                    ),
                    evidence="missing_keys=caller,correlation_id,trace_id,params",
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
                    status_extended="Logging configuration includes structured detail keys.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
