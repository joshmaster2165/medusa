"""TP-011: Invisible Unicode Characters in Tool Descriptions.

Scans tool descriptions, resource descriptions, and prompt descriptions for
zero-width characters, bidirectional override markers, and other invisible
Unicode codepoints.  These can hide injected instructions from human reviewers
while remaining visible to LLMs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_suspicious_unicode


class InvisibleUnicodeInDescriptionsCheck(BaseCheck):
    """Invisible Unicode Characters in Tool Descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        surfaces: list[tuple[str, str, str]] = []  # (resource_type, name, text)

        for tool in snapshot.tools or []:
            name = tool.get("name", "<unnamed>")
            desc = tool.get("description", "")
            if desc:
                surfaces.append(("tool", name, desc))

        for resource in snapshot.resources or []:
            name = resource.get("name", resource.get("uri", "<unnamed>"))
            desc = resource.get("description", "")
            if desc:
                surfaces.append(("resource", name, desc))

        for prompt in snapshot.prompts or []:
            name = prompt.get("name", "<unnamed>")
            desc = prompt.get("description", "")
            if desc:
                surfaces.append(("prompt", name, desc))

        if not surfaces:
            return findings

        for resource_type, name, text in surfaces:
            hits = find_suspicious_unicode(text)
            if hits:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type=resource_type,
                        resource_name=name,
                        status_extended=(
                            f"{resource_type.capitalize()} '{name}' contains "
                            f"invisible Unicode characters that may hide "
                            f"injected instructions: {'; '.join(hits[:3])}"
                        ),
                        evidence="; ".join(hits[:5]),
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
                        f"No invisible Unicode characters detected across "
                        f"{len(surfaces)} surface(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
