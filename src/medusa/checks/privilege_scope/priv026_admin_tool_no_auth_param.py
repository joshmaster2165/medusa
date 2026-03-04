"""PRIV026: Admin Tools Without Authorization Parameters.

Detects tools matching admin operation patterns such as create_user,
modify_role, grant_permission, and deploy that lack authorization
parameters like role, permission, scope, or token. Admin tools without
any authorization parameters represent a privilege escalation risk.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.filesystem import ADMIN_TOOL_PATTERNS

_AUTH_PARAM_NAMES: set[str] = {
    "role",
    "permission",
    "scope",
    "auth",
    "token",
    "authorization",
    "access_level",
    "privilege",
    "credentials",
    "api_key",
    "user_role",
    "auth_token",
}


class AdminToolNoAuthParamCheck(BaseCheck):
    """Admin Tools Without Authorization Parameters."""

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
            tool_name: str = tool.get("name", "<unnamed>")

            # Check if tool name matches any admin operation pattern
            is_admin_tool = False
            for pattern in ADMIN_TOOL_PATTERNS:
                if pattern.search(tool_name):
                    is_admin_tool = True
                    break

            if not is_admin_tool:
                continue

            # Examine inputSchema properties for auth params
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            has_auth_param = any(
                param_name.lower() in _AUTH_PARAM_NAMES for param_name in properties
            )

            if not has_auth_param:
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
                            f"Admin tool '{tool_name}' lacks authorization "
                            f"parameters. No role, permission, or scope "
                            f"parameters found in schema."
                        ),
                        evidence=(
                            f"admin_tool={tool_name}, param_names={list(properties.keys())[:10]}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.tools:
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
                    status_extended=(
                        f"No admin tools without authorization parameters "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
