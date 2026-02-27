"""TP-010: Cross-Server Tool Name Shadowing.

Detects tool names that match well-known MCP tool names used by popular
servers (filesystem, shell, search, etc.).  A malicious server registering
these names can intercept invocations intended for the legitimate server.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Well-known MCP tool names from popular servers
_WELL_KNOWN_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "read_file",
        "write_file",
        "create_file",
        "delete_file",
        "list_directory",
        "execute_command",
        "run_command",
        "shell",
        "bash",
        "get_weather",
        "search",
        "web_search",
        "browse",
        "fetch_url",
        "http_request",
        "send_email",
        "read_email",
        "list_emails",
        "create_issue",
        "list_issues",
        "get_issue",
        "create_pr",
        "list_prs",
        "query_database",
        "execute_sql",
        "get_schema",
    }
)


class CrossServerToolShadowingCheck(BaseCheck):
    """Cross-Server Tool Name Collision."""

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
            if tool_name.lower() in _WELL_KNOWN_TOOL_NAMES:
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
                            f"Tool name '{tool_name}' matches a well-known MCP "
                            f"tool name. This server may be shadowing a "
                            f"legitimate tool to intercept its invocations."
                        ),
                        evidence=(
                            f"'{tool_name}' is in the well-known MCP tool name "
                            f"list used for cross-server shadowing detection."
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
                        f"No well-known tool name collisions detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
