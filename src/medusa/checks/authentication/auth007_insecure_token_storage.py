"""AUTH007: Insecure Token Storage.

Detects authentication tokens stored in plaintext within configuration files, environment files,
or source code. Plaintext token storage exposes credentials to anyone with filesystem access,
version control access, or backup system access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_INSECURE_STORAGE_KEYS = {
    "localstorage",
    "local_storage",
    "sessionstorage",
    "session_storage",
    "plaintext",
    "plain_text",
    "file_storage",
    "disk",
}
_TOKEN_STORAGE_KEYS = {"token_storage", "credential_store", "auth_storage", "token_store"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, str) and any(s in v.lower() for s in _INSECURE_STORAGE_KEYS):
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


def _is_env_var_reference(value: str) -> bool:
    """Return True if the value is an environment variable reference like ${VAR} or $VAR."""
    stripped = value.strip()
    if stripped.startswith("${") and stripped.endswith("}"):
        return True
    if stripped.startswith("$") and stripped[1:].isidentifier():
        return True
    return False


def _has_plaintext_token_in_config(config: dict, depth: int = 0) -> str | None:
    """Return an evidence string if a token appears stored as plaintext in a config."""
    if depth > 10:
        return None
    token_keys = {"token", "api_key", "apikey", "secret", "password", "access_token"}
    for k, v in config.items():
        if k.lower() in token_keys and isinstance(v, str) and len(v) > 4:
            if not _is_env_var_reference(v):
                return f"Plaintext credential at config key '{k}'"
        if isinstance(v, dict):
            result = _has_plaintext_token_in_config(v, depth + 1)
            if result:
                return result
    return None


class InsecureTokenStorageCheck(BaseCheck):
    """Insecure Token Storage."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence = _has_plaintext_token_in_config(snapshot.config_raw or {})
        if evidence:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="token_storage",
                    status_extended=(
                        f"Server '{snapshot.server_name}' stores credentials in plaintext "
                        f"within configuration. Use environment variables or a secrets manager."
                    ),
                    evidence=evidence,
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
                resource_name="token_storage",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to store tokens in"
                    f"plaintext config."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
