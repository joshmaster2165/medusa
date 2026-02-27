"""PMT001: Prompt Argument Injection.

Detects MCP prompt templates that incorporate user-supplied arguments directly into prompt text
without sanitization or escaping. Malicious argument values can alter the prompt semantics,
inject new instructions, or override the intended prompt behavior.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_injection_phrases


class PromptArgumentInjectionCheck(BaseCheck):
    """Prompt Argument Injection."""

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
            arguments = prompt.get("arguments", [])

            for arg in arguments:
                arg_name = arg.get("name", "<unnamed>")
                arg_desc = arg.get("description", "")
                if not arg_desc:
                    continue
                phrases = find_injection_phrases(arg_desc)
                if phrases:
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
                                f"description contains injection phrases: "
                                f"{'; '.join(phrases[:3])}"
                            ),
                            evidence="; ".join(phrases[:5]),
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
                        f"No injection phrases detected in prompt argument "
                        f"descriptions across {len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
