"""SM015: Missing Secret Access Control.

Detects MCP servers where secrets are accessible to all server components, tools, and processes
without granular access controls. Missing access control on secrets means that any tool or code
running within the server can access all secrets regardless of whether it needs them.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_ACCESS_CONTROL_KEYS = {
    "secret_acl",
    "secret_rbac",
    "secret_policy",
    "access_policy",
    "secret_access_control",
    "acl",
    "rbac",
    "secret_permissions",
    "permissions",
    "access_control",
    "policy",
}


class MissingSecretAccessControlCheck(BaseCheck):
    """Missing Secret Access Control."""

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
            # Check every segment of the dotted key path, not just the leaf
            for segment in key.split("."):
                seg = segment.split("[")[0].lower()
                if seg in _ACCESS_CONTROL_KEYS:
                    found = True
                    break
            if found:
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
                        f"No secret access control configuration found for server "
                        f"'{snapshot.server_name}'. Secrets should have granular access controls."
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
                    f"Secret access control configuration detected for server "
                    f"'{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
