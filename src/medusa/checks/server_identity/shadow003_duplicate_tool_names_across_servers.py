"""SHADOW003: Duplicate Tool Names Across Servers.

Detects MCP servers with duplicate tool names that could enable tool shadowing attacks. When
multiple tools share the same name, an attacker-controlled server can shadow legitimate tools.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class DuplicateToolNamesAcrossServersCheck(BaseCheck):
    """Duplicate Tool Names Across Servers."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        # Check for duplicate tool names within this server
        seen: dict[str, int] = {}
        for tool in snapshot.tools:
            name = tool.get("name", "")
            if name:
                seen[name] = seen.get(name, 0) + 1

        duplicates = {n: c for n, c in seen.items() if c > 1}
        for name, count in duplicates.items():
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="tool",
                    resource_name=name,
                    status_extended=f"Tool name '{name}' appears {count} times — shadowing risk.",
                    evidence=f"tool={name}, count={count}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
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
                    status_extended=f"All {len(snapshot.tools)} tool names are unique.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
