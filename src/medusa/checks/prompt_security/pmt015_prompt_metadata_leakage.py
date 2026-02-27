"""PMT015: Prompt Metadata Leakage.

Detects MCP prompt definitions that expose sensitive metadata such as internal
system names, version strings, author information, API endpoint paths, or
development comments in their descriptions.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_METADATA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bv(?:ersion)?\s*\d+\.\d+\b", re.IGNORECASE),
    re.compile(r"\bauthor\s*:\s*\S+", re.IGNORECASE),
    re.compile(r"\bTODO\b|\bFIXME\b|\bHACK\b|\bXXX\b"),
    re.compile(r"\binternal\s+(?:api|endpoint|service|system)\b", re.IGNORECASE),
    re.compile(r"/api/v\d+/\w+"),  # internal API paths
    re.compile(r"\b(?:dev|staging|prod)(?:uction)?[-_\.]\w+", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
    re.compile(r"\binternal\s+(?:note|comment|only)\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+(?:share|expose|reveal|disclose)\b", re.IGNORECASE),
]


class PromptMetadataLeakageCheck(BaseCheck):
    """Prompt Metadata Leakage."""

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
            for pattern in _METADATA_PATTERNS:
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
                            f"Prompt '{prompt_name}' description leaks sensitive "
                            f"metadata: {'; '.join(hits[:3])}"
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
                        f"No metadata leakage detected across {len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
