"""PRIV-025: Unconstrained Shell Execution Parameters.

Detects tools with shell execution names (exec, shell, bash, run_command)
that have string parameters WITHOUT any constraints (no pattern, no enum,
no maxLength). Shell tools with completely unconstrained string inputs
create command injection vectors.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.filesystem import SHELL_TOOL_NAMES


class UnconstrainedShellExecutionCheck(BaseCheck):
    """Unconstrained Shell Execution Parameters."""

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

            if tool_name.lower() not in SHELL_TOOL_NAMES:
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            unconstrained: list[str] = []
            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue
                if param_def.get("type") != "string":
                    continue
                has_pattern = "pattern" in param_def
                has_enum = "enum" in param_def
                has_max_length = "maxLength" in param_def
                if not (has_pattern or has_enum or has_max_length):
                    unconstrained.append(param_name)

            if unconstrained:
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
                            f"Shell tool '{tool_name}' has unconstrained "
                            f"string parameters: "
                            f"{', '.join(unconstrained[:5])}. These lack "
                            f"pattern, enum, or maxLength constraints."
                        ),
                        evidence=(f"shell_tool={tool_name}, unconstrained_params={unconstrained}"),
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
                        f"No unconstrained shell execution parameters "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
