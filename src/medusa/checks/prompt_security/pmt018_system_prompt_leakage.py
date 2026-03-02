"""PMT-018: System Prompt Leakage.

Detects prompts that expose internal system instructions or configuration
in their description. Keywords suggesting system prompt content in
user-visible metadata indicate that confidential instructions may be
leaked to connected clients.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Phrases that suggest system prompt content is exposed
_LEAKAGE_PHRASES: list[str] = [
    "system prompt",
    "internal instructions",
    "you are a",
    "your role is",
    "do not reveal",
    "confidential instructions",
    "secret instructions",
    "system message",
    "hidden instructions",
    "do not disclose",
]

# Compile into a single regex for efficient scanning
_LEAKAGE_RE = re.compile(
    "|".join(re.escape(phrase) for phrase in _LEAKAGE_PHRASES),
    re.IGNORECASE,
)


class SystemPromptLeakageCheck(BaseCheck):
    """System Prompt Leakage."""

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
            description = prompt.get("description", "") or ""

            # Scan both name and description
            text_to_scan = f"{prompt_name} {description}"
            if not text_to_scan.strip():
                continue

            matches = _LEAKAGE_RE.findall(text_to_scan)
            if matches:
                unique_matches = list(dict.fromkeys(m.lower() for m in matches))
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
                            f"Prompt '{prompt_name}' description contains "
                            f"system prompt leakage phrases: "
                            f"{', '.join(repr(m) for m in unique_matches[:3])}"
                        ),
                        evidence="; ".join(unique_matches[:5]),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings:
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
                        f"No system prompt leakage detected in prompt "
                        f"descriptions across {len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
