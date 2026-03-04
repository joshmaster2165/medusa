"""TP043: State-Dependent Behavior Triggers.

Detects state-dependent activation patterns in tool descriptions, such as
usage counter triggers, threshold gates, first-run behavior, or temporal
activation. These patterns indicate tools that change behavior based on
internal state, consistent with the Tool Mutation TTP.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_STATE_TRIGGER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"after\s+\d+\s+(calls?|uses?|requests?|invocations?)",
            re.IGNORECASE,
        ),
        "usage counter trigger",
    ),
    (
        re.compile(
            r"(when|once|if)\s+(counter|threshold|limit)\s+(reaches?|exceeds?|hits?)",
            re.IGNORECASE,
        ),
        "threshold trigger",
    ),
    (
        re.compile(
            r"(once|after)\s+(activated|enabled|triggered|initialized)",
            re.IGNORECASE,
        ),
        "activation gate",
    ),
    (
        re.compile(
            r"(on|during)\s+(first|initial)\s+(run|call|use|execution)",
            re.IGNORECASE,
        ),
        "first-run trigger",
    ),
    (
        re.compile(
            r"subsequent\s+(calls?|uses?|requests?)\s+will",
            re.IGNORECASE,
        ),
        "behavioral shift",
    ),
    (
        re.compile(
            r"(behavior|mode)\s+(changes?|switches?|shifts?)\s+(after|when|once)",
            re.IGNORECASE,
        ),
        "mode switch",
    ),
    (
        re.compile(
            r"(time|date)\s*[-_]?\s*based\s+(activation|trigger|behavior)",
            re.IGNORECASE,
        ),
        "temporal trigger",
    ),
]


class StateDependentBehaviorTriggerCheck(BaseCheck):
    """State-Dependent Behavior Triggers in Tool Descriptions."""

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
            for pattern, label in _STATE_TRIGGER_PATTERNS:
                if pattern.search(all_text):
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
                            f"Tool '{tool_name}' contains state-dependent "
                            f"behavior triggers: {', '.join(matched[:3])}. "
                            f"Tools should have consistent behavior "
                            f"regardless of state."
                        ),
                        evidence=f"state_triggers={matched[:5]}",
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
                        f"No state-dependent behavior triggers detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
