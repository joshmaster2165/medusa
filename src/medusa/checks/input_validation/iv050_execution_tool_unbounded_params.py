"""IV-050: Detect unbounded string parameters on execution-oriented tools.

Flags tools whose *name* suggests execution (command, exec, run, shell, etc.)
and whose string parameters lack ANY constraint (no ``pattern``, ``enum``,
``maxLength``, or ``format``).  Unlike IV-001 which only inspects parameters
named after shell concepts, this check inspects **every** string parameter
on a tool that appears to be execution-oriented, catching cases where
innocuously-named parameters are still fed to a shell or interpreter.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

EXEC_TOOL_KEYWORDS: set[str] = {
    "command",
    "exec",
    "run",
    "shell",
    "query",
    "eval",
    "execute",
    "script",
    "bash",
    "terminal",
    "invoke",
    "call_tool",
}


class ExecutionToolUnboundedParamsCheck(BaseCheck):
    """Check for unconstrained string parameters on execution-oriented tools."""

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
            tool_name_lower = tool_name.lower()

            # Only inspect tools whose name suggests execution
            if not any(kw in tool_name_lower for kw in EXEC_TOOL_KEYWORDS):
                continue

            input_schema: dict | None = tool.get("inputSchema")
            if not input_schema or not isinstance(input_schema, dict):
                continue

            properties: dict = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue

                # Only inspect string parameters
                if param_def.get("type") != "string":
                    continue

                # Check whether the schema constrains the value
                has_constraint = any(
                    k in param_def for k in ("pattern", "enum", "maxLength", "format")
                )
                if has_constraint:
                    continue

                # FAIL - unbounded string on execution tool
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=f"{tool_name}.{param_name}",
                        status_extended=(
                            f"Execution tool '{tool_name}' has string "
                            f"parameter '{param_name}' with no constraints. "
                            f"The parameter lacks pattern, enum, maxLength, "
                            f"and format — any value can be supplied."
                        ),
                        evidence=(
                            f"tool={tool_name}, param={param_name}, "
                            f"type=string, pattern=N/A, enum=N/A, "
                            f"maxLength=N/A, format=N/A"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Emit a PASS if tools were scanned but no issues were found
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
                        f"No unbounded string parameters found on "
                        f"execution-oriented tools across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
