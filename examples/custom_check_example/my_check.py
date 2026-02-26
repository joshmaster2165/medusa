"""CUSTOM-001: Detect tools with no description.

A minimal example showing how to write a custom Medusa security check.
This check flags any MCP tool that has an empty or missing description,
which makes it impossible for users and LLMs to understand what the tool
does before invoking it.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class NoDescriptionCheck(BaseCheck):
    """Flag tools that have no description."""

    def metadata(self) -> CheckMetadata:
        """Load metadata from the sidecar YAML file."""
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        """Check every tool on the server for a missing description."""
        meta = self.metadata()
        findings: list[Finding] = []

        # If the server has no tools, the check is not applicable.
        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            description: str = tool.get("description", "").strip()

            if not description:
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
                            f"Tool '{tool_name}' has no description. Users and "
                            f"LLMs cannot determine its purpose before invocation."
                        ),
                        evidence=f"description field is empty or missing on tool '{tool_name}'",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Emit a PASS finding if all tools have descriptions
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
                        f"All {len(snapshot.tools)} tool(s) have descriptions."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
