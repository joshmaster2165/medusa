"""DP029: Missing Right to Deletion.

Checks whether the MCP server provides a mechanism for users to request deletion of their
personal data. The right to erasure is a fundamental requirement under GDPR and CCPA.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_TARGET_KEYS: set[str] = {
    "deletion",
    "erasure",
    "forget",
    "right_to_delete",
    "data_deletion",
    "purge_data",
    "erase",
    "gdpr_delete",
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


class RightToDeletionMissingCheck(BaseCheck):
    """Missing Right to Deletion."""

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
                    status_extended="No right-to-deletion or data erasure mechanism detected.",
                    evidence="missing_keys=deletion,erasure,forget",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        found = _walk_config(snapshot.config_raw, _TARGET_KEYS)
        if not found:
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
                    status_extended="No right-to-deletion or data erasure mechanism detected.",
                    evidence="missing_keys=deletion,erasure,forget",
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
                    status_extended="Data deletion/erasure mechanism detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
