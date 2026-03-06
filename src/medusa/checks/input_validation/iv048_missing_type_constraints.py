"""IV-048: Missing Type Constraints on String Parameters.

Detects string parameters in tool schemas that have no validation constraints
(no maxLength, pattern, enum, or format), making them unbounded input vectors.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class MissingTypeConstraintsCheck(BaseCheck):
    """Detect string parameters without any validation constraints."""

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
            tool_name = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {})

            unconstrained: list[str] = []
            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue
                if param_def.get("type") != "string":
                    continue

                has_max_length = "maxLength" in param_def
                has_pattern = "pattern" in param_def
                has_enum = "enum" in param_def
                has_format = "format" in param_def
                has_const = "const" in param_def

                if not (has_max_length or has_pattern or has_enum or has_format or has_const):
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
                            f"Tool '{tool_name}' has {len(unconstrained)} string "
                            f"parameter(s) with no validation constraints (no maxLength, "
                            f"pattern, enum, or format). Unconstrained string inputs are "
                            f"potential injection vectors."
                        ),
                        evidence=f"unconstrained_params={unconstrained[:10]}",
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
                        f"All string parameters across {len(snapshot.tools)} tool(s) "
                        f"have at least one validation constraint."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
