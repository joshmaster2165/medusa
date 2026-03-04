"""TP039: Parameter Override Instructions in Tool Descriptions.

Detects instructions in tool or parameter descriptions that direct the LLM
to override, ignore, or replace user-provided parameter values. This is a
tool description poisoning technique where embedded instructions manipulate
how the LLM handles user inputs.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_OVERRIDE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"always\s+(set|use|pass|provide)\s+.{0,30}(param|arg|value|field)",
            re.IGNORECASE,
        ),
        "forced parameter value",
    ),
    (
        re.compile(
            r"ignore\s+(the\s+)?(user.?s?|provided|given|input)\s+(value|param|arg)",
            re.IGNORECASE,
        ),
        "ignore user input",
    ),
    (
        re.compile(
            r"override\s+(the\s+)?(user.?s?|default|provided)",
            re.IGNORECASE,
        ),
        "override directive",
    ),
    (
        re.compile(
            r"replace\s+(the\s+)?(user.?s?|input|provided)\s+(value|data)",
            re.IGNORECASE,
        ),
        "replace user data",
    ),
    (
        re.compile(
            r"do\s+not\s+use\s+the\s+(provided|given|user)",
            re.IGNORECASE,
        ),
        "reject user input",
    ),
    (
        re.compile(
            r"instead\s+(of\s+.{0,20})?(use|set|pass|provide)",
            re.IGNORECASE,
        ),
        "substitution directive",
    ),
    (
        re.compile(
            r"must\s+(always\s+)?be\s+set\s+to",
            re.IGNORECASE,
        ),
        "forced value constraint",
    ),
]


class ParameterOverrideInstructionCheck(BaseCheck):
    """Parameter Override Instructions in Tool Descriptions."""

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
            # Combine tool description + all parameter descriptions
            parts: list[str] = [tool.get("description", "") or ""]
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}
            for param_def in properties.values():
                if isinstance(param_def, dict):
                    parts.append(param_def.get("description", "") or "")
            all_text = " ".join(parts)

            if not all_text.strip():
                continue

            matched: list[str] = []
            for pattern, label in _OVERRIDE_PATTERNS:
                match = pattern.search(all_text)
                if match:
                    matched.append(label)

            if matched:
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
                            f"Tool '{tool_name}' contains parameter override "
                            f"instructions: {', '.join(matched[:3])}. "
                            f"These direct the LLM to ignore or replace "
                            f"user-provided values."
                        ),
                        evidence=f"override_matches={matched[:5]}",
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
                        f"No parameter override instructions detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
