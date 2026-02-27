"""PMT013: Missing Prompt Length Limit.

Detects MCP prompt definitions whose string arguments do not define a maxLength
constraint.  Without length limits, extremely long argument values can exhaust
the LLM context window or enable injection through context overflow.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class PromptLengthLimitCheck(BaseCheck):
    """Missing Prompt Length Limit."""

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
                arg_type = arg.get("type", "string")

                if arg_type != "string":
                    continue
                if "maxLength" in arg:
                    continue

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
                            f"Prompt '{prompt_name}' string argument '{arg_name}' "
                            f"has no maxLength constraint, allowing unbounded input "
                            f"that may overflow the LLM context window."
                        ),
                        evidence=(f"arg '{arg_name}' type=string, no maxLength defined"),
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
                        f"All prompt string arguments across "
                        f"{len(snapshot.prompts)} prompt(s) have maxLength defined."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
