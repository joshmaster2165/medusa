"""DP-004: Detect excessive data exposure from bulk export tools.

Checks for tools whose names match data-dump patterns (e.g. "dump_all",
"export_data", "bulk_fetch") but whose inputSchema lacks pagination
parameters such as "limit", "offset", "page", or "cursor".
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import DATA_DUMP_PATTERNS, PAGINATION_PARAMS


class ExcessiveDataExposureCheck(BaseCheck):
    """Check for bulk export tools missing pagination parameters."""

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

            # Check if tool name matches a data-dump pattern
            is_dump_tool = any(pattern.search(tool_name) for pattern in DATA_DUMP_PATTERNS)
            if not is_dump_tool:
                continue

            # Check if inputSchema has pagination parameters
            input_schema = tool.get("inputSchema", {})
            schema_properties = input_schema.get("properties", {})
            param_names = {p.lower() for p in schema_properties.keys()}

            has_pagination = bool(param_names & PAGINATION_PARAMS)

            if not has_pagination:
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
                            f"Tool '{tool_name}' appears to be a bulk export tool "
                            f"but has no pagination parameters (e.g. limit, offset, "
                            f"page, cursor) in its inputSchema."
                        ),
                        evidence=(
                            f"Tool name: '{tool_name}', "
                            f"parameters: {sorted(param_names) if param_names else 'none'}"
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Emit PASS if tools were checked but none had issues
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
                        f"No unbounded bulk export tools detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
