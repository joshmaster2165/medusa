"""DP030: Unbounded Array Parameters.

Detects tool parameters with type "array" that lack maxItems constraints.
Without maxItems, attackers can send massive arrays causing memory exhaustion
or enabling bulk data operations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class UnboundedArrayParamsCheck(BaseCheck):
    """Unbounded Array Parameters."""

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
            input_schema = tool.get("inputSchema", {})
            if not isinstance(input_schema, dict):
                continue
            properties = input_schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue
                param_type = param_def.get("type", "")
                if param_type != "array":
                    continue

                has_max_items = "maxItems" in param_def
                if not has_max_items:
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=(snapshot.transport_type),
                            resource_type="tool",
                            resource_name=tool_name,
                            status_extended=(
                                f"Tool '{tool_name}' parameter "
                                f"'{param_name}' is type array "
                                f"without maxItems constraint."
                            ),
                            evidence=(f"param={param_name}, type=array, maxItems=missing"),
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
                        "All array parameters have maxItems "
                        f"constraints across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
