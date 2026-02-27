"""TP-007: Schema Poisoning via Injected Descriptions.

Scans inputSchema property descriptions for prompt-injection phrases and hidden
tags.  Attackers embed malicious instructions in per-parameter descriptions
that are invisible in most UIs but interpreted by the LLM as directives.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_hidden_tags, find_injection_phrases


class SchemaPoisoningCheck(BaseCheck):
    """Schema Poisoning via Default Values."""

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
            properties = input_schema.get("properties", {})

            for param_name, param_def in properties.items():
                if not isinstance(param_def, dict):
                    continue
                desc: str = param_def.get("description", "")
                if not desc:
                    continue

                issues: list[str] = []
                hidden = find_hidden_tags(desc)
                if hidden:
                    issues.append(f"Hidden tags: {'; '.join(hidden[:3])}")
                phrases = find_injection_phrases(desc)
                if phrases:
                    issues.append(f"Injection phrases: {'; '.join(phrases[:3])}")

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
                            resource_name=f"{tool_name}.{param_name}",
                            status_extended=(
                                f"Schema parameter '{param_name}' of tool "
                                f"'{tool_name}' contains poisoned description: "
                                f"{'; '.join(issues)}"
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
                        f"No schema poisoning detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
