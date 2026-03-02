"""AGENT-022: Missing Tool Annotations.

Detects tools that lack MCP annotations (readOnlyHint,
destructiveHint, idempotentHint, openWorldHint) that help LLM
clients make informed safety decisions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Severity, Status
from medusa.utils.heuristics import ToolRisk, classify_tool_risk

_ANNOTATION_HINTS: list[str] = [
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
]


class MissingToolAnnotationsCheck(BaseCheck):
    """Missing Tool Annotations."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(
        self, snapshot: ServerSnapshot
    ) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        tools_without_annotations: list[str] = []
        destructive_without: list[str] = []

        for tool in snapshot.tools:
            tool_name = tool.get("name", "unknown")
            annotations = tool.get("annotations")

            has_hints = False
            if isinstance(annotations, dict):
                has_hints = any(
                    annotations.get(hint) is not None
                    for hint in _ANNOTATION_HINTS
                )

            if not has_hints:
                tools_without_annotations.append(tool_name)
                risk = classify_tool_risk(tool)
                if risk in (
                    ToolRisk.DESTRUCTIVE,
                    ToolRisk.PRIVILEGED,
                ):
                    destructive_without.append(tool_name)

        if not tools_without_annotations:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    "All tools have MCP annotations with "
                    "safety hints."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
            return findings

        total = len(snapshot.tools)
        missing_count = len(tools_without_annotations)
        pct = (missing_count / total) * 100

        # Escalate severity if >50% lack annotations AND
        # destructive tools are present
        effective_severity = meta.severity
        if pct > 50 and destructive_without:
            effective_severity = Severity.MEDIUM

        # Report destructive tools without annotations first
        for tool_name in destructive_without:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.FAIL,
                severity=effective_severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="tool",
                resource_name=tool_name,
                status_extended=(
                    f"Destructive/privileged tool "
                    f"'{tool_name}' lacks MCP annotations. "
                    f"LLM clients cannot determine safety "
                    f"constraints."
                ),
                evidence=(
                    f"Tool: {tool_name}, "
                    f"Missing: annotations object with "
                    f"readOnlyHint/destructiveHint/"
                    f"idempotentHint/openWorldHint"
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))

        # Summary finding for non-destructive tools
        other_missing = [
            t for t in tools_without_annotations
            if t not in destructive_without
        ]
        if other_missing:
            sample = other_missing[:5]
            suffix = ""
            if len(other_missing) > 5:
                suffix = (
                    f" and {len(other_missing) - 5} more"
                )
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.FAIL,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended=(
                    f"{missing_count}/{total} tools "
                    f"({pct:.0f}%) lack MCP annotations."
                ),
                evidence=(
                    f"Tools without annotations: "
                    f"{', '.join(sample)}{suffix}"
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))

        return findings
