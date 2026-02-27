"""IV020: Missing Type Constraint.

Detects tool parameters without explicit type definitions in their JSON Schema. Parameters
lacking a type constraint accept any JSON value, making it impossible to validate input
structure and enabling type confusion attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_VALID_TYPES: frozenset[str] = frozenset(
    {"string", "number", "integer", "boolean", "array", "object", "null"}
)


class MissingTypeConstraintCheck(BaseCheck):
    """Missing Type Constraint."""

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

                param_type = param_def.get("type")

                # Has explicit enum acts as a type-like constraint
                has_enum = bool(param_def.get("enum"))
                if has_enum:
                    continue

                if param_type and param_type in _VALID_TYPES:
                    continue

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
                            f"Tool '{tool_name}' parameter '{param_name}' lacks an explicit "
                            f"'type' field (got: {param_type!r}). "
                            f"Without type constraints, any JSON value is accepted, enabling "
                            f"type confusion attacks."
                        ),
                        evidence=(
                            f"param={param_name}, type={param_type!r} "
                            f"(not in {sorted(_VALID_TYPES)})"
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
                        f"All parameters have explicit type constraints defined "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
