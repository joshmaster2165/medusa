"""SM011: Secret Sprawl.

Detects MCP server deployments where the same secret is duplicated across multiple locations
such as configuration files, environment variables, scripts, and documentation. Secret sprawl
makes it impossible to effectively rotate or revoke secrets because copies persist in unknown
locations.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
_SPRAWL_THRESHOLD = 3  # More than this many distinct secret locations = sprawl


class SecretSprawlCheck(BaseCheck):
    """Secret Sprawl."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if not snapshot.config_raw and not snapshot.env:
            return []

        secret_locations: list[str] = []
        if snapshot.config_raw:
            for key, value in _flatten_config(snapshot.config_raw):
                if value and _SECRET_KEY_RE.search(key):
                    secret_locations.append(key)
        for var in snapshot.env:
            if _SECRET_KEY_RE.search(var):
                secret_locations.append(f"env.{var}")

        if len(secret_locations) > _SPRAWL_THRESHOLD:
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
                        f"Secret sprawl detected: {len(secret_locations)} secret-like values "
                        f"across config for server '{snapshot.server_name}' "
                        f"(threshold: {_SPRAWL_THRESHOLD})."
                    ),
                    evidence=f"Secret locations: {', '.join(secret_locations[:5])}",
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
                    f"Secret count within acceptable threshold for server '{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
