"""SM019: Weak Default Password Patterns.

Detects tool parameter defaults that match common weak passwords.
Only checks parameters whose names suggest they hold password or
credential values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Common weak passwords (compared case-insensitively).
_WEAK_PASSWORDS: set[str] = {
    "password",
    "123456",
    "admin",
    "root",
    "test",
    "guest",
    "default",
    "changeme",
    "letmein",
    "welcome",
    "monkey",
    "master",
    "qwerty",
    "abc123",
    "password1",
    "password123",
    "admin123",
    "root123",
    "1234567890",
    "pass@123",
    "p@ssw0rd",
    "admin@123",
}

# Parameter name substrings that suggest the value is a password/credential.
_PASSWORD_PARAM_INDICATORS: list[str] = [
    "password",
    "passwd",
    "pass",
    "secret",
    "credential",
    "auth",
]


class WeakDefaultPasswordsCheck(BaseCheck):
    """Weak Default Password Patterns."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name = tool.get("name", "unknown")
            schema = tool.get("inputSchema") or {}
            properties = schema.get("properties") or {}

            self._walk_properties(
                properties,
                tool_name,
                meta,
                snapshot,
                findings,
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
                    status_extended="No weak default passwords detected in tool parameters.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings

    def _walk_properties(
        self,
        properties: dict[str, Any],
        tool_name: str,
        meta: CheckMetadata,
        snapshot: ServerSnapshot,
        findings: list[Finding],
        prefix: str = "",
    ) -> None:
        """Recursively walk JSON Schema properties for weak default passwords."""
        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue

            full_name = f"{prefix}{param_name}" if not prefix else f"{prefix}.{param_name}"
            param_lower = param_name.lower()

            # Only check params whose names suggest passwords
            is_password_param = any(
                indicator in param_lower for indicator in _PASSWORD_PARAM_INDICATORS
            )

            if is_password_param:
                default = param_def.get("default")
                if isinstance(default, str) and default.lower() in _WEAK_PASSWORDS:
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="tool",
                            resource_name=tool_name,
                            status_extended=(
                                f"Tool '{tool_name}' parameter '{full_name}' has a weak "
                                f"default password value."
                            ),
                            evidence=f"Parameter: {full_name}, Default: {default}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

            # Recurse into nested object properties
            nested_props = param_def.get("properties")
            if isinstance(nested_props, dict):
                self._walk_properties(
                    nested_props,
                    tool_name,
                    meta,
                    snapshot,
                    findings,
                    full_name,
                )
