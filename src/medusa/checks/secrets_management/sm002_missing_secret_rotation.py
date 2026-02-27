"""SM002: Missing Secret Rotation.

Detects MCP servers that use long-lived secrets without a rotation policy or mechanism. Secrets
that are never rotated remain valid indefinitely, extending the window of opportunity for
compromised credentials to be exploited.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.credentials import SECRET_ROTATION_KEYS


def _has_rotation_config(config: dict) -> bool:
    for key, _value in _flatten_config(config):
        leaf = key.split(".")[-1].split("[")[0].lower()
        if leaf in SECRET_ROTATION_KEYS:
            return True
    return False


class MissingSecretRotationCheck(BaseCheck):
    """Missing Secret Rotation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if not snapshot.config_raw:
            return []

        found = _has_rotation_config(snapshot.config_raw)
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
                        f"No secret rotation configuration found for server "
                        f"'{snapshot.server_name}'. Secrets should be rotated regularly."
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
                    f"Secret rotation configuration detected for server '{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
