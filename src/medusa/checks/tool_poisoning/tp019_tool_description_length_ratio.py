"""TP019: Abnormal Description-to-Name Length Ratio.

Detects tools with suspiciously long descriptions relative to their parameter count. An
extremely high description-to-param ratio may indicate that the description contains hidden
instructions, encoded payloads, or excessive content designed to influence LLM behaviour beyond
documenting the tool's legitimate purpose.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Maximum characters per parameter before flagging
_RATIO_THRESHOLD: int = 500


class ToolDescriptionLengthRatioCheck(BaseCheck):
    """Abnormal Description-to-Name Length Ratio."""

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
            description: str = tool.get("description", "")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_count = max(len(properties), 1)  # avoid division by zero
            desc_len = len(description)
            ratio = desc_len / param_count

            if ratio > _RATIO_THRESHOLD:
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
                            f"Tool '{tool_name}' has a description-to-parameter "
                            f"ratio of {ratio:.0f} chars/param "
                            f"(threshold {_RATIO_THRESHOLD}). "
                            f"Description length: {desc_len}, params: {param_count}."
                        ),
                        evidence=(
                            f"ratio={ratio:.0f} (desc={desc_len} chars, "
                            f"params={param_count}, threshold={_RATIO_THRESHOLD})"
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
                        f"All {len(snapshot.tools)} tool(s) have acceptable "
                        f"description-to-parameter ratios."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
