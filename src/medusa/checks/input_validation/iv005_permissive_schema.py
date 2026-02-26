"""IV-005: Detect overly permissive MCP tool input schemas.

Flags schemas that:
- Set ``additionalProperties: true`` (or omit it entirely, since JSON Schema
  defaults to ``true``).
- Declare ``properties`` but have no ``required`` array.

Both conditions widen the attack surface by accepting unexpected or incomplete
input from the LLM.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class PermissiveSchemaCheck(BaseCheck):
    """Check for schemas that are too permissive."""

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

            if not input_schema or not isinstance(input_schema, dict):
                # Missing schemas are handled by IV-004
                continue

            properties = input_schema.get("properties")
            if not isinstance(properties, dict) or len(properties) == 0:
                # No properties to validate against -- IV-004 covers this
                continue

            issues: list[str] = []

            # -- additionalProperties check --
            additional = input_schema.get("additionalProperties")
            if additional is True:
                issues.append(
                    "additionalProperties is explicitly set to true"
                )
            elif additional is None:
                # JSON Schema defaults to true when omitted
                issues.append(
                    "additionalProperties is not set (defaults to true)"
                )

            # -- required check --
            required = input_schema.get("required")
            if required is None:
                issues.append(
                    "No 'required' array is defined; all parameters are "
                    "optional"
                )
            elif isinstance(required, list) and len(required) == 0:
                issues.append(
                    "'required' is an empty list; all parameters are optional"
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
                            f"Tool '{tool_name}' has an overly permissive "
                            f"input schema: {'; '.join(issues)}."
                        ),
                        evidence=(
                            f"additionalProperties="
                            f"{input_schema.get('additionalProperties', '<unset>')}, "
                            f"required="
                            f"{input_schema.get('required', '<unset>')}, "
                            f"property_count={len(properties)}"
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
                        f"All {len(snapshot.tools)} tool schema(s) properly "
                        f"restrict additional properties and define required "
                        f"fields."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
