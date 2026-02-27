"""TP014: Recursive Tool Invocation Risk.

Detects tool descriptions that encourage or instruct the LLM to invoke additional tools in a
recursive or chained fashion. Malicious descriptions can create tool invocation loops or chains
that escalate privileges, exfiltrate data across multiple steps, or cause denial of service.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_RECURSIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"call\s+this\s+tool", re.IGNORECASE),
    re.compile(r"invoke\s+this\s+tool", re.IGNORECASE),
    re.compile(r"then\s+call\s+\w+", re.IGNORECASE),
    re.compile(r"then\s+invoke\s+\w+", re.IGNORECASE),
    re.compile(r"after\s+(calling|invoking|running)\s+this", re.IGNORECASE),
    re.compile(r"recursively\s+call", re.IGNORECASE),
    re.compile(r"call\s+itself", re.IGNORECASE),
    re.compile(r"self[-_]?invoke", re.IGNORECASE),
]


class RecursiveToolInvocationRiskCheck(BaseCheck):
    """Recursive Tool Invocation Risk."""

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

            hits: list[str] = []
            # Also check for "invoke <tool_name>" self-reference pattern
            self_ref = re.compile(rf"invoke\s+{re.escape(tool_name)}", re.IGNORECASE)
            for m in self_ref.finditer(description):
                hits.append(m.group()[:80])

            for pattern in _RECURSIVE_PATTERNS:
                for m in pattern.finditer(description):
                    hits.append(m.group()[:80])

            if hits:
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
                            f"Tool '{tool_name}' description encourages "
                            f"recursive or chained tool invocation: "
                            f"{'; '.join(hits[:3])}"
                        ),
                        evidence="; ".join(hits[:5]),
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
                        f"No recursive tool invocation patterns detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
