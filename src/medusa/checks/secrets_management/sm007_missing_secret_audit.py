"""SM007: Missing Secret Access Audit.

Detects MCP servers that do not log or audit access to secrets. Without secret access auditing,
it is impossible to determine who accessed which secrets, when access occurred, or whether
access was authorized after a security incident.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_AUDIT_KEYS = {
    "audit",
    "audit_log",
    "secret_audit",
    "access_log",
    "access_audit",
    "audit_trail",
    "secret_logging",
    "audit_enabled",
}


class MissingSecretAuditCheck(BaseCheck):
    """Missing Secret Access Audit."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if not snapshot.config_raw:
            return []

        found = False
        for key, _value in _flatten_config(snapshot.config_raw):
            leaf = key.split(".")[-1].split("[")[0].lower()
            if leaf in _AUDIT_KEYS:
                found = True
                break

        if not found:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name=snapshot.config_file_path or "config",
                    status_extended=(
                        f"No secret access audit configuration found for server "
                        f"'{snapshot.server_name}'. Secret access should be logged."
                    ),
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
                resource_type="config",
                resource_name=snapshot.config_file_path or "config",
                status_extended=(
                    f"Secret access audit configuration detected for server "
                    f"'{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
