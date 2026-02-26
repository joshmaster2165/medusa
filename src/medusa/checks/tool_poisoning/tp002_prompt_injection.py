"""TP-002: Detect prompt injection phrases in MCP tool descriptions.

Scans every tool description and parameter description for explicit prompt
injection phrases such as "ignore previous instructions", "do not tell the
user", "secretly", and other patterns defined in the pattern-matching module.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_injection_phrases


class PromptInjectionCheck(BaseCheck):
    """Check for prompt injection phrases in tool descriptions."""

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

            # Collect all text surfaces to scan: description + param descriptions
            text_surfaces: list[tuple[str, str]] = []
            if description:
                text_surfaces.append(("description", description))

            input_schema = tool.get("inputSchema", {})
            schema_properties = input_schema.get("properties", {})
            for param_name, param_def in schema_properties.items():
                param_desc: str = param_def.get("description", "")
                if param_desc:
                    text_surfaces.append(
                        (f"parameter '{param_name}' description", param_desc)
                    )

            for surface_label, text in text_surfaces:
                injection_matches = find_injection_phrases(text)
                if injection_matches:
                    # Deduplicate while preserving order
                    unique_phrases = list(dict.fromkeys(injection_matches))
                    phrase_list = ", ".join(
                        f"'{p}'" for p in unique_phrases[:5]
                    )

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
                                f"Tool '{tool_name}' {surface_label} contains "
                                f"prompt injection phrase(s): {phrase_list}"
                            ),
                            evidence="; ".join(unique_phrases[:10]),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # Emit PASS if no injection phrases were found
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
                        f"No prompt injection phrases detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
