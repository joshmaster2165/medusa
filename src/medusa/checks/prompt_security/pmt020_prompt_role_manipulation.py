"""PMT-020: Prompt Role Manipulation.

Detects prompts whose names or descriptions suggest role manipulation
capabilities such as impersonation, privilege escalation, or identity
switching. Phrases like "act as", "impersonate", "set role", or
"elevate" indicate the prompt may allow overriding intended roles.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Phrases that indicate role manipulation attempts
_ROLE_MANIPULATION_PHRASES: list[str] = [
    "set role",
    "change role",
    "as admin",
    "act as",
    "impersonate",
    "pretend to be",
    "override role",
    "system role",
    "assume role",
    "switch role",
    "elevate",
    "become",
]

# Compile into a single regex for efficient scanning
_MANIPULATION_RE = re.compile(
    "|".join(re.escape(phrase) for phrase in _ROLE_MANIPULATION_PHRASES),
    re.IGNORECASE,
)


class PromptRoleManipulationCheck(BaseCheck):
    """Prompt Role Manipulation."""

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
            matches = _MANIPULATION_RE.findall(text_to_scan)

            if matches:
                unique_matches = list(dict.fromkeys(m.lower() for m in matches))
                # Determine which fields matched
                name_matches = _MANIPULATION_RE.findall(prompt_name)
                desc_matches = _MANIPULATION_RE.findall(description)
                locations: list[str] = []
                if name_matches:
                    locations.append("name")
                if desc_matches:
                    locations.append("description")

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
                            f"Prompt '{prompt_name}' contains role manipulation "
                            f"phrases in its {' and '.join(locations)}: "
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
                        f"No role manipulation phrases detected across "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
