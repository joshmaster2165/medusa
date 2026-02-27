"""PMT010: Prompt Output Manipulation.

Detects MCP prompt definitions that instruct the LLM to manipulate its output
format or destination — for example, outputting data as JSON to an external URL,
or suppressing safety disclaimers.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_OUTPUT_MANIPULATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"output\s+(?:only|as|in)\s+(?:json|xml|yaml|csv|raw)", re.IGNORECASE),
    re.compile(r"suppress\s+(?:any|all|safety|disclaimer)", re.IGNORECASE),
    re.compile(r"do\s+not\s+add\s+(?:any\s+)?disclaimer", re.IGNORECASE),
    re.compile(r"skip\s+(?:any\s+)?(?:warning|disclaimer|safety)", re.IGNORECASE),
    re.compile(r"format\s+(?:the\s+)?output\s+as\b", re.IGNORECASE),
    re.compile(r"redirect\s+(?:the\s+)?output\s+to\b", re.IGNORECASE),
    re.compile(r"send\s+(?:the\s+)?output\s+to\b", re.IGNORECASE),
    re.compile(r"write\s+(?:the\s+)?output\s+to\b", re.IGNORECASE),
    re.compile(r"omit\s+(?:any|all|the)?\s*(?:preamble|intro|warning)", re.IGNORECASE),
]


class PromptOutputManipulationCheck(BaseCheck):
    """Prompt Output Manipulation."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.prompts:
            return findings

        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "<unnamed>")
            description = prompt.get("description", "")

            hits: list[str] = []
            for pattern in _OUTPUT_MANIPULATION_PATTERNS:
                for m in pattern.finditer(description):
                    hits.append(m.group()[:100])

            if hits:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="prompt",
                        resource_name=prompt_name,
                        status_extended=(
                            f"Prompt '{prompt_name}' contains output manipulation "
                            f"instructions: {'; '.join(hits[:3])}"
                        ),
                        evidence="; ".join(hits[:5]),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.prompts:
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
                        f"No output manipulation instructions detected across "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
