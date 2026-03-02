"""IV044: Missing Required Field Declaration.

Detects tool input schemas that declare properties but have an empty or missing
required array. When no fields are marked as required, attackers can call the tool
with an empty object, potentially triggering unintended default behaviors, null
reference errors, or bypassing expected input validation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class MissingRequiredFieldsCheck(BaseCheck):
    """Missing Required Field Declaration."""

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
            if not isinstance(properties, dict) or not properties:
                # Skip tools with no declared properties
                continue

            required: list = input_schema.get("required", [])
            if not isinstance(required, list):
                required = []

            if len(required) > 0:
                continue

            prop_count = len(properties)
            prop_names = ", ".join(list(properties.keys())[:5])
            if prop_count > 5:
                prop_names += f", ... (+{prop_count - 5} more)"

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
                        f"Tool '{tool_name}' declares {prop_count} "
                        f"parameter(s) but has no required fields. "
                        f"The tool can be called with an empty object, "
                        f"potentially triggering default behaviors or "
                        f"null reference errors."
                    ),
                    evidence=(
                        f"tool={tool_name}, properties=[{prop_names}], "
                        f"required=[]"
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
                        f"All tools with properties declare required fields "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
