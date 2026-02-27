"""CTX005: Context Poisoning via Resource Content.

Detects MCP resource content that contains adversarial text designed to manipulate LLM behavior.
Malicious resources can embed hidden instructions that the LLM follows when processing the
content.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_hidden_tags, find_injection_phrases


class ContextPoisoningViaResourcesCheck(BaseCheck):
    """Context Poisoning via Resource Content."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        for resource in snapshot.resources:
            res_name = resource.get("name", "<unnamed>")
            desc = resource.get("description") or ""
            uri = str(resource.get("uri") or "")
            text = desc + " " + uri

            if not text.strip():
                continue

            issues: list[str] = []
            tags = find_hidden_tags(text)
            if tags:
                issues.append(f"Hidden tags: {'; '.join(tags[:3])}")
            phrases = find_injection_phrases(text)
            if phrases:
                unique = list(dict.fromkeys(phrases))
                issues.append(f"Injection phrases: {', '.join(repr(p) for p in unique[:3])}")

            if issues:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=res_name,
                        status_extended=(
                            f"Resource '{res_name}' contains adversarial context-poisoning "
                            f"content that may manipulate LLM behavior."
                        ),
                        evidence="; ".join(issues),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.resources:
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
                        f"No context-poisoning content detected across "
                        f"{len(snapshot.resources)} resource(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
