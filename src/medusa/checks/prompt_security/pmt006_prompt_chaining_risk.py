"""PMT006: Prompt Chaining Risk.

Detects MCP prompt definitions that reference or invoke other prompts or tools,
creating chains where the output of one feeds into another.  Uncontrolled
chaining can amplify injection attacks.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CHAINING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"call\s+(?:the\s+)?prompt\b", re.IGNORECASE),
    re.compile(r"use\s+(?:the\s+)?prompt\b", re.IGNORECASE),
    re.compile(r"invoke\s+(?:the\s+)?prompt\b", re.IGNORECASE),
    re.compile(r"use\s+(?:the\s+)?tool\b", re.IGNORECASE),
    re.compile(r"call\s+(?:the\s+)?tool\b", re.IGNORECASE),
    re.compile(r"then\s+(?:call|use|invoke)\b", re.IGNORECASE),
    re.compile(r"chain(?:ed)?\s+with\b", re.IGNORECASE),
    re.compile(r"followed\s+by\b", re.IGNORECASE),
]


class PromptChainingRiskCheck(BaseCheck):
    """Prompt Chaining Risk."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.prompts:
            return findings

        prompt_names = {p.get("name", "") for p in snapshot.prompts}

        for prompt in snapshot.prompts:
            prompt_name = prompt.get("name", "<unnamed>")
            description = prompt.get("description", "")

            hits: list[str] = []
            for pattern in _CHAINING_PATTERNS:
                for m in pattern.finditer(description):
                    hits.append(m.group()[:80])

            # Also check if another prompt's name is mentioned
            for other_name in prompt_names:
                if other_name and other_name != prompt_name and other_name in description:
                    hits.append(f"references other prompt '{other_name}'")

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
                            f"Prompt '{prompt_name}' description references "
                            f"chaining to other prompts or tools: "
                            f"{'; '.join(hits[:3])}"
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
                        f"No prompt chaining risks detected across "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
