"""AUDIT007: Sensitive Data in Logs.

Detects MCP server logging configurations or patterns that write sensitive data such as PII,
credentials, or API keys to log files. Sensitive data in logs creates secondary exposure
vectors.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import LOGGING_CONFIG_KEYS

_REDACTION_KEYS: set[str] = {
    "log_redact",
    "redact",
    "log_filter",
    "mask_sensitive",
    "sanitize_logs",
    "log_masking",
    "pii_filter",
    "scrub",
    "log_sanitize",
    "redaction",
}

_DANGEROUS_LOG_KEYS: dict[str, set[str]] = {
    "log_pii": {"true", "1", "yes", "enabled"},
    "log_credentials": {"true", "1", "yes", "enabled"},
    "log_secrets": {"true", "1", "yes", "enabled"},
    "log_tokens": {"true", "1", "yes", "enabled"},
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


def _find_dangerous_log_settings(config: Any, _depth: int = 0) -> list[str]:
    hits: list[str] = []
    if _depth > 10:
        return hits
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(key, str) and key.lower() in _DANGEROUS_LOG_KEYS:
                val_str = str(value).lower()
                if val_str in _DANGEROUS_LOG_KEYS[key.lower()]:
                    hits.append(f"{key}={value}")
            if isinstance(value, dict):
                hits.extend(_find_dangerous_log_settings(value, _depth + 1))
    return hits


class SensitiveDataInLogsCheck(BaseCheck):
    """Sensitive Data in Logs."""

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
            return findings  # No logging → audit001 handles

        # Check for dangerous log settings
        if snapshot.config_raw:
            dangerous = _find_dangerous_log_settings(snapshot.config_raw)
            for hit in dangerous:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="config",
                        resource_name=hit.split("=")[0],
                        status_extended=f"Dangerous log setting enables sensitive data logging:"
                        f"{hit}",
                        evidence=hit,
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Check for missing redaction config
        has_redaction = (
            _walk_config(snapshot.config_raw, _REDACTION_KEYS) if snapshot.config_raw else False
        )
        if not has_redaction and not findings:
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
                    status_extended="Logging is configured but no log redaction/masking/filtering"
                    "keys found.",
                    evidence="missing_keys=log_redact,mask_sensitive,sanitize_logs",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if not findings:
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
                    status_extended="Log redaction or sensitive data filtering is configured.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
