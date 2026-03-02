"""INTG018: Schema-Less Tools.

Detects tools with no inputSchema or an empty inputSchema. Without a
schema, there is no contract for parameter validation, allowing
arbitrary data to be passed to the tool.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_NO_PARAM_INDICATORS: set[str] = {
    "no parameters",
    "no arguments",
    "takes no input",
    "no input required",
    "requires no input",
    "no params",
    "parameterless",
}


def _genuinely_no_params(tool: dict) -> bool:
    """Check if description says the tool has no parameters."""
    desc = tool.get("description", "").lower()
    return any(
        indicator in desc
        for indicator in _NO_PARAM_INDICATORS
    )


class SchemalessToolsCheck(BaseCheck):
    """Schema-Less Tools."""

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

            # Skip tools that genuinely have no parameters
            if _genuinely_no_params(tool):
                continue

            input_schema = tool.get("inputSchema")

            is_missing = (
                input_schema is None
                or not isinstance(input_schema, dict)
            )
            is_empty = (
                isinstance(input_schema, dict)
                and not input_schema
            )
            has_no_properties = (
                isinstance(input_schema, dict)
                and input_schema
                and "properties" not in input_schema
            )

            if is_missing or is_empty or has_no_properties:
                reason = "missing"
                if is_empty:
                    reason = "empty"
                elif has_no_properties:
                    reason = "no properties key"

                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=(
                            snapshot.transport_type
                        ),
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' has no "
                            f"valid inputSchema "
                            f"({reason}). No parameter "
                            f"validation contract exists."
                        ),
                        evidence=(
                            f"inputSchema={reason}"
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
                    server_transport=(
                        snapshot.transport_type
                    ),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"All tools have valid input "
                        f"schemas across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
