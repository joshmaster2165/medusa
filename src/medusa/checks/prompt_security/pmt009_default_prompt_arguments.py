"""PMT009: Dangerous Default Prompt Arguments.

Detects MCP prompt definitions with default argument values that contain
injection phrases or other dangerous content.  Defaults are used silently when
clients omit the argument.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.text_analysis import find_injection_phrases


class DefaultPromptArgumentsCheck(BaseCheck):
    """Dangerous Default Prompt Arguments."""

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
                default_val = arg.get("default", None)
                if default_val is None:
                    continue

                default_str = str(default_val)
                phrases = find_injection_phrases(default_str)
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
                                f"has a dangerous default value containing "
                                f"injection phrases: {'; '.join(phrases[:3])}"
                            ),
                            evidence=(
                                f"default='{default_str[:120]}'; phrases: {'; '.join(phrases[:3])}"
                            ),
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
                        f"No dangerous default argument values detected across "
                        f"{len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
