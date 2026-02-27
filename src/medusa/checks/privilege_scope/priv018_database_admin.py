"""PRIV-018: Database Admin Operations.

Detects tools with DDL or administrative database capability (CREATE TABLE,
DROP TABLE, GRANT, ALTER, TRUNCATE), indicating superuser-level DB access.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_DB_ADMIN_PATTERN = re.compile(
    r"\b(create\s+(table|database|schema|index|user)|"
    r"drop\s+(table|database|schema|index|user)|"
    r"alter\s+(table|database|schema|user)|"
    r"grant\s+|revoke\s+|truncate\s+(table|database)?|"
    r"db_admin|database_admin|db_create|db_drop|"
    r"admin_query|execute_ddl)\b",
    re.IGNORECASE,
)


class DatabaseAdminCheck(BaseCheck):
    """Detect tools with database admin (DDL/GRANT) capability."""

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

            match = _DB_ADMIN_PATTERN.search(searchable)
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
                        f"Tool '{tool_name}' has database admin capability "
                        f"('{match.group(0)}'), granting DDL/GRANT-level DB access."
                    ),
                    evidence=f"DB admin keyword: {match.group(0)}",
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
                    status_extended="No database admin tools detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
