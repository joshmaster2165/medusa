"""IV-003: Detect SQL-injection risk in MCP tool input schemas.

Scans every tool's ``inputSchema`` for string parameters whose names match
known SQL identifiers (``query``, ``sql``, ``where``, ``statement``, etc.) and
flags those that accept raw string input without ``pattern`` or ``enum``
constraints.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import SQL_PARAM_NAMES


class SqlInjectionCheck(BaseCheck):
    """Check for unconstrained SQL parameters in tool schemas."""

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

                if param_def.get("type") != "string":
                    continue

                normalised = param_name.lower().strip()
                if normalised not in SQL_PARAM_NAMES:
                    continue

                # Check for constraining keywords
                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))
                has_max_length = (
                    isinstance(param_def.get("maxLength"), int)
                    and param_def["maxLength"] <= 128
                )

                if has_pattern or has_enum:
                    continue

                severity_note = ""
                if has_max_length:
                    # A short maxLength reduces risk slightly but does not
                    # eliminate it -- still flag but note the partial control.
                    severity_note = (
                        f" A maxLength of {param_def['maxLength']} is set, "
                        f"which limits but does not prevent SQL injection."
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
                            f"Tool '{tool_name}' has a parameter "
                            f"'{param_name}' that suggests raw SQL input "
                            f"but lacks `pattern` or `enum` constraints.{severity_note}"
                        ),
                        evidence=(
                            f"param={param_name}, type=string, "
                            f"pattern={param_def.get('pattern', 'N/A')}, "
                            f"enum={param_def.get('enum', 'N/A')}, "
                            f"maxLength={param_def.get('maxLength', 'N/A')}"
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
                        f"No unconstrained SQL parameters detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
