"""HARD008: Insecure Default Credentials.

Detects MCP servers that ship with default usernames, passwords, API keys, or tokens that are
documented, predictable, or shared across all installations. Default credentials are the most
common entry point for server compromise.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_DEFAULT_CRED_VALUES = {
    "admin",
    "password",
    "default",
    "changeme",
    "secret",
    "123456",
    "admin123",
    "test",
    "pass",
    "letmein",
}
_CRED_KEYS = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "token",
    "credential",
    "username",
    "user",
    "default_password",
}


def _has_default_cred_value(
    config: Any, cred_keys: set[str], default_vals: set[str], _depth: int = 0
) -> str | None:
    """Walk config for credential keys with default values."""
    if _depth > 10:
        return None
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(key, str) and key.lower() in cred_keys:
                if isinstance(value, str) and value.lower() in default_vals:
                    return f"{key}={value!r}"
            result = _has_default_cred_value(value, cred_keys, default_vals, _depth + 1)
            if result:
                return result
    elif isinstance(config, list):
        for item in config:
            result = _has_default_cred_value(item, cred_keys, default_vals, _depth + 1)
            if result:
                return result
    return None


class InsecureDefaultCredentialsCheck(BaseCheck):
    """Insecure Default Credentials."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        match = _has_default_cred_value(snapshot.config_raw or {}, _CRED_KEYS, _DEFAULT_CRED_VALUES)
        if match:
            return [
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
                        f"Server '{snapshot.server_name}' uses a default or weak credential: "
                        f"{match}. Change default credentials before deployment."
                    ),
                    evidence=match,
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
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to use "
                    f"default credentials in its configuration."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
