"""GOV021: Missing Tool Namespace.

Detects tools that lack organizational namespace prefixes. Without
namespaces, tool name collisions between multiple MCP servers are
more likely, reducing governance and traceability.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_NAMESPACE_SEPARATORS: set[str] = {".", "/", "::"}


def _has_namespace(tool_name: str) -> bool:
    """Check if a tool name contains a namespace separator."""
    return any(sep in tool_name for sep in _NAMESPACE_SEPARATORS)


class MissingToolNamespaceCheck(BaseCheck):
    """Missing Tool Namespace."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        total_tools = len(snapshot.tools)

        # Only meaningful with more than 5 tools
        if total_tools <= 5:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server has {total_tools} tool(s)."
                        f" Namespace check applies to "
                        f"servers with more than 5 tools."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        tools_without_ns: list[str] = []
        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            if not _has_namespace(tool_name):
                tools_without_ns.append(tool_name)

        no_ns_count = len(tools_without_ns)
        ratio = no_ns_count / total_tools

        if ratio > 0.5:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"has {no_ns_count}/{total_tools} "
                        f"tools without namespace prefixes "
                        f"({ratio:.0%}). Namespace "
                        f"separators: ., /, ::"
                    ),
                    evidence=(f"no_namespace={', '.join(tools_without_ns[:10])}"),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(snapshot.transport_type),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Majority of tools "
                        f"({total_tools - no_ns_count}/"
                        f"{total_tools}) use namespace "
                        f"prefixes."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
