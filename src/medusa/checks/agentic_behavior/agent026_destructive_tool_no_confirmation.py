"""AGENT026: Destructive Tool Without Confirmation Parameter.

Detects tools classified as DESTRUCTIVE (delete, remove, drop, etc.)
that lack a confirmation or dry-run parameter in their schema. Without
such a safety mechanism, the LLM can execute irreversible actions with
no opportunity for user approval at the tool level.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk
from medusa.utils.patterns.agentic import CONFIRMATION_SCHEMA_PARAMS


class DestructiveToolNoConfirmationCheck(BaseCheck):
    """Destructive Tool Without Confirmation Parameter."""

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
            risk = classify_tool_risk(tool)

            if risk != ToolRisk.DESTRUCTIVE:
                continue

            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            param_names = {p.lower() for p in properties}
            has_confirm = bool(param_names & CONFIRMATION_SCHEMA_PARAMS)

            if not has_confirm:
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
                            f"Tool '{tool_name}' is classified as "
                            f"DESTRUCTIVE but has no confirmation or "
                            f"dry-run parameter. Irreversible actions "
                            f"can execute without safety checks."
                        ),
                        evidence=(
                            f"risk={risk.value}, "
                            f"params={sorted(param_names)[:10]}, "
                            f"confirm_param=missing"
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
                        f"All destructive tools have confirmation "
                        f"parameters, or no destructive tools found "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
