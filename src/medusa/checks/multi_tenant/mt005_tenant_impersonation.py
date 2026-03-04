"""MT005: Tenant Impersonation Risk.

Detects MCP server auth-related tools that accept a tenant-switching parameter
but do not require re-authentication, enabling one tenant to impersonate
another through token manipulation or session hijacking.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.multi_tenant import TENANT_ID_PARAMS

_IMPERSONATION_PREVENTION_KEYS = {
    "tenant_impersonation_protection",
    "anti_impersonation",
    "tenant_token_binding",
    "tenant_session_binding",
    "prevent_tenant_switch",
    "tenant_mfa",
}

# Keywords in tool name/description that indicate auth-related tools
_AUTH_TOOL_KEYWORDS = {
    "auth", "login", "session", "token", "authenticate",
    "sso", "oauth", "saml", "identity", "signin", "sign_in",
}

# Parameters that indicate re-authentication is required
_REAUTH_PARAMS = {
    "password", "credentials", "mfa_code", "otp", "totp",
    "verification_code", "challenge_response", "confirm_password",
    "current_password", "auth_token", "re_authenticate",
}


def _walk_config_for_keys(config: Any, keys: set[str], _depth: int = 0) -> bool:
    """Recursively walk config dict looking for any of the given keys."""
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in keys:
                return True
            if _walk_config_for_keys(config[key], keys, _depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk_config_for_keys(item, keys, _depth + 1):
                return True
    return False


def _is_auth_tool(tool: dict) -> bool:
    """Check if a tool is auth-related based on its name or description."""
    name = tool.get("name", "").lower().replace("-", "_")
    description = tool.get("description", "").lower()
    name_tokens = set(name.split("_"))
    desc_tokens = set(description.split())
    combined = name_tokens | desc_tokens
    return bool(combined & _AUTH_TOOL_KEYWORDS)


class TenantImpersonationCheck(BaseCheck):
    """Tenant Impersonation Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        has_config_mitigation = _walk_config_for_keys(
            snapshot.config_raw, _IMPERSONATION_PREVENTION_KEYS,
        )

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")

            if not _is_auth_tool(tool):
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}

            has_tenant_param = bool(param_names & TENANT_ID_PARAMS)
            has_reauth_param = bool(param_names & _REAUTH_PARAMS)

            # Auth tool allows tenant switching without re-authentication
            if has_tenant_param and not has_reauth_param and not has_config_mitigation:
                findings.append(Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=tool_name,
                    status_extended=(
                        f"Auth tool '{tool_name}' accepts a tenant-switching "
                        f"parameter without requiring re-authentication. "
                        f"One tenant may impersonate another."
                    ),
                    evidence=(
                        f"tenant_params={sorted(param_names & TENANT_ID_PARAMS)}, "
                        f"reauth_param=missing"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                ))

        if not findings and snapshot.tools:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    "Auth tools either require re-authentication for tenant "
                    "switching, do not expose tenant-switching parameters, "
                    "or impersonation protection is configured at the server level."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))

        return findings
