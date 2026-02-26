"""PRIV-003: Detect shell-execution capability in MCP tools.

Identifies tools whose names match known shell/command execution identifiers
(``exec``, ``run_command``, ``shell``, ``bash``, ``terminal``, etc.). These are
**always** flagged as critical because direct shell access is the highest
privilege an MCP tool can grant, regardless of any schema constraints.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import SHELL_TOOL_NAMES


class ShellExecutionCheck(BaseCheck):
    """Check for tools that provide shell execution capability."""

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
            normalised = tool_name.lower().strip()

            if normalised not in SHELL_TOOL_NAMES:
                continue

            # Build evidence about the tool's configuration
            evidence_parts: list[str] = [
                f"tool_name={tool_name}",
            ]

            # Note any description that confirms shell intent
            description = tool.get("description", "")
            if description:
                evidence_parts.append(
                    f"description={description[:200]}"
                )

            # Check if there are any mitigation signals in the schema
            mitigations: list[str] = []
            input_schema = tool.get("inputSchema")
            if input_schema and isinstance(input_schema, dict):
                properties = input_schema.get("properties", {})
                if isinstance(properties, dict):
                    for param_name, param_def in properties.items():
                        if not isinstance(param_def, dict):
                            continue
                        if param_def.get("enum"):
                            mitigations.append(
                                f"'{param_name}' has enum constraint"
                            )
                        if param_def.get("pattern"):
                            mitigations.append(
                                f"'{param_name}' has pattern constraint"
                            )

            mitigation_note = ""
            if mitigations:
                mitigation_note = (
                    f" Schema-level constraints detected "
                    f"({'; '.join(mitigations)}), but these do not "
                    f"eliminate the risk of shell execution."
                )

            # Always flag -- shell execution is inherently critical
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
                        f"Tool '{tool_name}' provides shell/command "
                        f"execution capability. This grants the LLM full "
                        f"operating-system-level access on the server host, "
                        f"equivalent to remote code execution.{mitigation_note}"
                    ),
                    evidence="; ".join(evidence_parts),
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
                        f"No shell execution tools detected among "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
