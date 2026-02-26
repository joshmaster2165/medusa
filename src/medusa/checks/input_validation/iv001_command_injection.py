"""IV-001: Detect command-injection risk in MCP tool input schemas.

Scans every tool's ``inputSchema`` for string parameters whose names match
known shell/command execution identifiers (``command``, ``cmd``, ``exec``, etc.)
and flags those that lack ``pattern`` or ``enum`` constraints, meaning an
attacker-controlled value could inject arbitrary shell commands.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import SHELL_PARAM_NAMES


class CommandInjectionCheck(BaseCheck):
    """Check for unconstrained shell/command parameters in tool schemas."""

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

                # Check if the parameter name suggests shell execution
                normalised = param_name.lower().strip()
                if normalised not in SHELL_PARAM_NAMES:
                    continue

                # Check whether the schema constrains the value
                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))

                if has_pattern or has_enum:
                    continue

                # Unconstrained shell parameter -- flag it
                constraint_hint = (
                    "No `pattern` or `enum` constraint is defined"
                )
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
                            f"Tool '{tool_name}' has a string parameter "
                            f"'{param_name}' that suggests shell/command "
                            f"execution but accepts unconstrained input. "
                            f"{constraint_hint}."
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"enum={param_def.get('enum', 'N/A')}"
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
                        f"No unconstrained command-injection parameters "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
