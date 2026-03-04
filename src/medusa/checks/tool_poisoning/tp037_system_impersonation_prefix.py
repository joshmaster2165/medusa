"""TP037: System Impersonation Prefix in Tool Descriptions.

Detects system role impersonation prefixes in tool or parameter descriptions,
such as "System:", "[SYSTEM]", "ADMIN:", and ChatML markers like ``<|system|>``,
``<|im_start|>system``, ``<<SYS>>``. These patterns attempt to override LLM
behavior by impersonating system messages.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_IMPERSONATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|\n)\s*System:\s", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"\[ADMIN\]", re.IGNORECASE),
    re.compile(r"(?:^|\n)\s*ADMIN:\s"),
    re.compile(r"<\|system\|>", re.IGNORECASE),
    re.compile(r"<\|assistant\|>", re.IGNORECASE),
    re.compile(r"<\|im_start\|>system", re.IGNORECASE),
    re.compile(r"<<SYS>>", re.IGNORECASE),
]


class SystemImpersonationPrefixCheck(BaseCheck):
    """System Impersonation Prefix in Tool Descriptions."""

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
            for pattern in _IMPERSONATION_PATTERNS:
                match = pattern.search(all_text)
                if match:
                    matched.append(match.group(0))

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
                            f"Tool '{tool_name}' contains system "
                            f"impersonation prefixes: "
                            f"{', '.join(matched[:3])}. These attempt to "
                            f"override LLM behavior by faking system "
                            f"messages."
                        ),
                        evidence=f"impersonation_matches={matched[:5]}",
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
                        f"No system impersonation prefixes detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
