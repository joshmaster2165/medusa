"""DP014: Missing Data Anonymization.

Detects MCP servers that handle PII-related tool parameters without anonymization, pseudonymization,
or hashing configuration. Processing PII without anonymization violates privacy-by-design
    principles.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_PII_PARAM_NAMES: set[str] = {
    "name",
    "email",
    "phone",
    "address",
    "ssn",
    "date_of_birth",
    "ip_address",
    "username",
    "first_name",
    "last_name",
    "social_security",
}
_ANON_KEYS: set[str] = {
    "anonymize",
    "pseudonymize",
    "hash",
    "mask",
    "obfuscate",
    "anonymization",
    "data_masking",
    "pii_protection",
    "redact",
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


class MissingDataAnonymizationCheck(BaseCheck):
    """Missing Data Anonymization."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_pii = False
        for tool in snapshot.tools:
            schema = tool.get("inputSchema") or {}
            props = schema.get("properties") or {}
            if any(p.lower() in _PII_PARAM_NAMES for p in props):
                has_pii = True
                break

        if not has_pii:
            return findings

        has_anon = _walk_config(snapshot.config_raw, _ANON_KEYS) if snapshot.config_raw else False
        if not has_anon:
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
                    status_extended="Tools handle PII but no anonymization/masking configuration"
                    "detected.",
                    evidence="missing_keys=anonymize,pseudonymize,hash,mask",
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
                    status_extended="Data anonymization configuration detected for PII-handling"
                    "tools.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
