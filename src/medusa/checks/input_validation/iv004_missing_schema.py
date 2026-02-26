"""IV-004: Detect MCP tools with missing or empty input schemas.

Flags tools that either:
- Have no ``inputSchema`` key at all.
- Have an ``inputSchema`` that is empty or contains no ``properties``.

Tools without schemas accept completely unvalidated input.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class MissingSchemaCheck(BaseCheck):
    """Check for tools that lack a defined input schema."""

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
            input_schema = tool.get("inputSchema")

            issues: list[str] = []

            if input_schema is None:
                issues.append("No inputSchema is defined")
            elif not isinstance(input_schema, dict):
                issues.append(
                    f"inputSchema is not an object (got {type(input_schema).__name__})"
                )
            else:
                properties = input_schema.get("properties")
                schema_type = input_schema.get("type")

                if not schema_type:
                    issues.append(
                        "inputSchema is missing the 'type' field"
                    )

                if properties is None:
                    issues.append(
                        "inputSchema has no 'properties' defined"
                    )
                elif isinstance(properties, dict) and len(properties) == 0:
                    # An empty properties dict is intentional for zero-arg
                    # tools -- only flag if the schema also lacks 'type'.
                    if not schema_type:
                        issues.append(
                            "inputSchema has empty 'properties' and no 'type'"
                        )

            if issues:
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
                            f"Tool '{tool_name}' has an incomplete or "
                            f"missing input schema: {'; '.join(issues)}. "
                            f"This tool accepts unvalidated input."
                        ),
                        evidence="; ".join(issues),
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
                        f"All {len(snapshot.tools)} tool(s) have a defined "
                        f"input schema with properties."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
