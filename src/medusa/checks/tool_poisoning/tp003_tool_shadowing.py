"""TP-003: Detect tool shadowing and namespace collisions.

Performs two sub-checks:
1. Duplicate tool names within the same server (always a problem).
2. Tools whose names match well-known tool names from popular MCP servers,
   which could shadow legitimate tools in multi-server environments.

The cross-server duplicate check (comparing tools across different servers)
happens at the scan-engine level and is outside the scope of this per-server
check.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status

# Well-known tool names from popular MCP servers that are common shadowing
# targets.  This list is intentionally broad; a collision does not prove
# malice, but it warrants review in multi-server configurations.
_WELL_KNOWN_TOOL_NAMES: set[str] = {
    # Filesystem servers
    "read_file",
    "write_file",
    "list_directory",
    "create_directory",
    "move_file",
    "copy_file",
    "delete_file",
    "read_multiple_files",
    "search_files",
    "get_file_info",
    # Git / GitHub servers
    "git_clone",
    "git_commit",
    "git_diff",
    "git_log",
    "git_status",
    "create_pull_request",
    "create_issue",
    "search_repositories",
    "search_code",
    # Database / SQL servers
    "execute_sql",
    "query",
    "read_query",
    "write_query",
    "list_tables",
    "describe_table",
    # Shell / execution servers
    "execute",
    "run_command",
    "run",
    "bash",
    "shell",
    "exec",
    # Web / fetch servers
    "fetch",
    "http_request",
    "web_search",
    "search",
    # Memory / knowledge servers
    "store_memory",
    "retrieve_memory",
    "search_memory",
    "create_entities",
    "search_nodes",
}


class ToolShadowingCheck(BaseCheck):
    """Check for duplicate and shadow-prone tool names."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        tool_names: list[str] = [
            tool.get("name", "") for tool in snapshot.tools
        ]

        # --- Sub-check 1: Duplicate names within the server ----------------
        name_counts = Counter(tool_names)
        for name, count in name_counts.items():
            if count > 1:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=name,
                        status_extended=(
                            f"Tool name '{name}' is registered {count} times "
                            f"within server '{snapshot.server_name}'. "
                            f"Duplicate tool names cause unpredictable "
                            f"dispatch behaviour."
                        ),
                        evidence=f"Occurrences: {count}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # --- Sub-check 2: Collision with well-known tool names -------------
        unique_names = set(tool_names)
        collisions = unique_names & _WELL_KNOWN_TOOL_NAMES
        for name in sorted(collisions):
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=name,
                    status_extended=(
                        f"Tool '{name}' on server '{snapshot.server_name}' "
                        f"matches a well-known tool name. In multi-server "
                        f"environments this could shadow a legitimate tool "
                        f"from another server."
                    ),
                    evidence=f"Matches well-known tool name: {name}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        # PASS if no issues found
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
                    status_extended=(
                        f"No duplicate or shadow-prone tool names detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
