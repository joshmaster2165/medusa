"""IV049: Excessive Enum Values Indicating Data Leak.

Detects tool parameters with an unusually large number of enum values that may
expose internal data such as user IDs, database records, or system configurations
through the schema itself.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

ENUM_THRESHOLD = 50


class ExcessiveEnumExposureCheck(BaseCheck):
    """Excessive Enum Values Indicating Data Leak."""

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

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue
                enum_vals = param_def.get("enum", [])
                if not isinstance(enum_vals, list):
                    continue
                if len(enum_vals) > ENUM_THRESHOLD:
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
                                f"Tool '{tool_name}' parameter '{param_name}' "
                                f"has {len(enum_vals)} enum values (threshold: "
                                f"{ENUM_THRESHOLD}). Excessive enum values may "
                                f"expose internal data such as user IDs, database "
                                f"records, or system configurations."
                            ),
                            evidence=(
                                f"enum_count={len(enum_vals)}, sample_values={enum_vals[:5]}"
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
                        f"No excessive enum values found across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
