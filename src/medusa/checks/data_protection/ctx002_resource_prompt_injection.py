"""CTX-002: Detect hidden instructions and prompt injection in resources and prompts.

Scans resource descriptions, prompt descriptions, and prompt argument
descriptions for hidden XML/HTML tags and prompt injection phrases.
This complements TP-001 and TP-002 which focus on tool descriptions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_hidden_tags, find_injection_phrases


class ResourcePromptInjectionCheck(BaseCheck):
    """Check for hidden instructions and prompt injection in resource/prompt definitions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # --- Scan resources ---
        for resource in snapshot.resources:
            res_name: str = resource.get("name", "<unnamed>")
            description: str = resource.get("description", "")

            if not description:
                continue

            issues: list[str] = []

            hidden_tags = find_hidden_tags(description)
            if hidden_tags:
                issues.append(
                    f"Hidden tags found: {'; '.join(hidden_tags[:5])}"
                )

            injection_matches = find_injection_phrases(description)
            if injection_matches:
                unique_phrases = list(dict.fromkeys(injection_matches))
                issues.append(
                    f"Injection phrases: {', '.join(f'{p!r}' for p in unique_phrases[:5])}"
                )

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
                            f"Resource '{res_name}' description contains "
                            f"injection content: {'; '.join(issues)}"
                        ),
                        evidence="; ".join(issues),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # --- Scan prompts ---
        for prompt in snapshot.prompts:
            prompt_name: str = prompt.get("name", "<unnamed>")
            prompt_desc: str = prompt.get("description", "")

            # Scan prompt description
            if prompt_desc:
                issues = []
                hidden_tags = find_hidden_tags(prompt_desc)
                if hidden_tags:
                    issues.append(
                        f"Hidden tags found: {'; '.join(hidden_tags[:5])}"
                    )
                injection_matches = find_injection_phrases(prompt_desc)
                if injection_matches:
                    unique_phrases = list(dict.fromkeys(injection_matches))
                    issues.append(
                        f"Injection phrases: {', '.join(f'{p!r}' for p in unique_phrases[:5])}"
                    )
                if issues:
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
                                f"injection content: {'; '.join(issues)}"
                            ),
                            evidence="; ".join(issues),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

            # Scan prompt argument descriptions
            arguments = prompt.get("arguments", [])
            for arg in arguments:
                arg_name: str = arg.get("name", "<unnamed>")
                arg_desc: str = arg.get("description", "")

                if not arg_desc:
                    continue

                issues = []
                hidden_tags = find_hidden_tags(arg_desc)
                if hidden_tags:
                    issues.append(
                        f"Hidden tags found: {'; '.join(hidden_tags[:5])}"
                    )
                injection_matches = find_injection_phrases(arg_desc)
                if injection_matches:
                    unique_phrases = list(dict.fromkeys(injection_matches))
                    issues.append(
                        f"Injection phrases: {', '.join(f'{p!r}' for p in unique_phrases[:5])}"
                    )
                if issues:
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="prompt",
                            resource_name=f"{prompt_name}.{arg_name}",
                            status_extended=(
                                f"Prompt '{prompt_name}' argument '{arg_name}' "
                                f"description contains injection content: "
                                f"{'; '.join(issues)}"
                            ),
                            evidence="; ".join(issues),
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )

        # Emit PASS if items were checked but none had issues
        has_content = snapshot.resources or snapshot.prompts
        if not findings and has_content:
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
                        f"No injection content detected across "
                        f"{len(snapshot.resources)} resource(s) and "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
