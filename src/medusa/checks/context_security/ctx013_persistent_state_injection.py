"""CTX013: Persistent State Injection in Tool Descriptions.

Detects instructions in tool or parameter descriptions that attempt to persist
behavioral changes across interactions, such as "from now on", "always do",
"never forget", "update your instructions". These commands attempt to reprogram
LLM behavior through tool metadata as described in the Prompt State Manipulation TTP.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_PERSISTENCE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"from\s+now\s+on", re.IGNORECASE), "from now on"),
    (
        re.compile(r"always\s+(do|use|prefer|remember|include|apply|set|call)\b", re.IGNORECASE),
        "always directive",
    ),
    (
        re.compile(r"never\s+(forget|ignore|skip|remove|stop|omit|discard)\b", re.IGNORECASE),
        "never directive",
    ),
    (re.compile(r"remember\s+(this|that|to\s+always)\b", re.IGNORECASE), "remember command"),
    (
        re.compile(r"update\s+(your|the)\s+(instructions?|behavior|rules?|config)", re.IGNORECASE),
        "instruction update",
    ),
    (
        re.compile(r"for\s+all\s+future\s+(requests?|interactions?|calls?)", re.IGNORECASE),
        "future persistence",
    ),
    (
        re.compile(r"in\s+every\s+(response|interaction|conversation|request)", re.IGNORECASE),
        "universal directive",
    ),
    (re.compile(r"permanently\s+(change|set|update|modify)", re.IGNORECASE), "permanent change"),
]


class PersistentStateInjectionCheck(BaseCheck):
    """Persistent State Injection in Tool Descriptions."""

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
            for pattern, label in _PERSISTENCE_PATTERNS:
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
                            f"Tool '{tool_name}' contains persistent state "
                            f"injection patterns: {', '.join(matched[:3])}. "
                            f"These attempt to reprogram LLM behavior across "
                            f"interactions."
                        ),
                        evidence=f"persistence_matches={matched[:5]}",
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
                        f"No persistent state injection patterns detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
