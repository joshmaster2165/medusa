"""TP-001: Detect hidden instructions embedded in MCP tool descriptions.

Scans every tool description for:
- Hidden XML/HTML-style tags (e.g. <IMPORTANT>, <SYSTEM>, <!-- -->)
- Invisible Unicode characters (zero-width spaces, directional overrides, etc.)

These techniques allow attackers to inject instructions that are invisible in
user interfaces but interpreted by language models.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_hidden_tags, find_suspicious_unicode


class HiddenInstructionsCheck(BaseCheck):
    """Check for hidden instructions in tool descriptions."""

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

            if not description:
                continue

            issues: list[str] = []

            # Check for hidden XML/HTML tags
            hidden_tags = find_hidden_tags(description)
            if hidden_tags:
                issues.append(
                    f"Hidden tags found: {'; '.join(hidden_tags[:5])}"
                )

            # Check for invisible Unicode characters
            suspicious_chars = find_suspicious_unicode(description)
            if suspicious_chars:
                issues.append(
                    f"Suspicious Unicode characters: {'; '.join(suspicious_chars[:5])}"
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
                            f"Tool '{tool_name}' contains hidden instructions "
                            f"in its description: {'; '.join(issues)}"
                        ),
                        evidence="; ".join(issues),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

            # Also scan inputSchema description fields for hidden content
            input_schema = tool.get("inputSchema", {})
            schema_properties = input_schema.get("properties", {})
            for param_name, param_def in schema_properties.items():
                param_desc: str = param_def.get("description", "")
                if not param_desc:
                    continue

                param_issues: list[str] = []
                param_hidden = find_hidden_tags(param_desc)
                if param_hidden:
                    param_issues.append(
                        f"Hidden tags: {'; '.join(param_hidden[:3])}"
                    )
                param_unicode = find_suspicious_unicode(param_desc)
                if param_unicode:
                    param_issues.append(
                        f"Suspicious Unicode: {'; '.join(param_unicode[:3])}"
                    )

                if param_issues:
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
                                f"Parameter '{param_name}' of tool '{tool_name}' "
                                f"contains hidden instructions: "
                                f"{'; '.join(param_issues)}"
                            ),
                            evidence="; ".join(param_issues),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # If tools were checked but none had issues, emit a PASS finding
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
                        f"No hidden instructions detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
