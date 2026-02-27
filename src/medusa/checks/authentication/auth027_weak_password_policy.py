"""AUTH027: Weak Password Policy.

Detects MCP server authentication configurations with password requirements below security
standards. Weak password policies allow short, simple, or commonly used passwords that are
easily guessed or cracked.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_PASSWORD_POLICY_KEYS = {
    "password_policy",
    "password_strength",
    "min_password_length",
    "password_requirements",
    "min_length",
    "complexity",
}
_WEAK_INDICATORS = {"min_length": 8, "minlength": 8}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


def _find_weak_length(config: dict, depth: int = 0) -> int | None:
    """Return the configured min password length if it is weak (<= 8)."""
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in ("min_length", "minlength", "min_password_length") and isinstance(v, int):
            if v <= 8:
                return v
        if isinstance(v, dict):
            result = _find_weak_length(v, depth + 1)
            if result is not None:
                return result
    return None


class WeakPasswordPolicyCheck(BaseCheck):
    """Weak Password Policy."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_policy = _walk_config(snapshot.config_raw or {}, _PASSWORD_POLICY_KEYS)
        if not has_policy:
            return []
        weak_len = _find_weak_length(snapshot.config_raw or {})
        if weak_len is not None:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="password_policy",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has a weak password policy: "
                        f"minimum length of {weak_len} is below the recommended 12 characters."
                    ),
                    evidence=f"min_length = {weak_len} (recommended >= 12)",
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
                resource_name="password_policy",
                status_extended=(
                    f"Server '{snapshot.server_name}' password policy meets minimum requirements."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
