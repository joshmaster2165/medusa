"""PRIV-014: User Management Operations.

Detects tools that can create, modify, or delete system users/groups,
enabling backdoor account creation and privilege escalation.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_USER_MGMT_PATTERN = re.compile(
    r"\b(useradd|userdel|usermod|adduser|deluser|groupadd|groupdel|"
    r"create_user|delete_user|add_user|remove_user|modify_user|"
    r"passwd|chpasswd|net\s+user|manage.*user|user.*manage)\b",
    re.IGNORECASE,
)


class UserManagementCheck(BaseCheck):
    """Detect tools with user/group management capability."""

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
            tool_name = tool.get("name", "<unnamed>")
            description = tool.get("description", "") or ""
            schema_str = str(tool.get("inputSchema") or {})
            searchable = f"{tool_name} {description} {schema_str}"

            match = _USER_MGMT_PATTERN.search(searchable)
            if not match:
                continue

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
                        f"Tool '{tool_name}' has user management capability "
                        f"('{match.group(0)}'), enabling backdoor account creation."
                    ),
                    evidence=f"User management keyword: {match.group(0)}",
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
                    status_extended="No user management tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
