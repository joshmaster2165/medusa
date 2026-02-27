"""PMT005: Missing Prompt Sanitization.

Detects MCP prompt arguments that accept free-form string input without any
constraining pattern, enum, or maxLength defined in their schema.  This is
analogous to the IV-checks for tool parameters but applied to prompt arguments.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status


class MissingPromptSanitizationCheck(BaseCheck):
    """Missing Prompt Sanitization."""

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
                # MCP prompt arguments may have a schema-like "type" field
                arg_type = arg.get("type", "string")
                has_pattern = "pattern" in arg
                has_enum = "enum" in arg
                has_max_length = "maxLength" in arg

                if arg_type == "string" and not (has_pattern or has_enum or has_max_length):
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
                                f"accepts unconstrained string input (no pattern, "
                                f"enum, or maxLength). Injection payloads can "
                                f"reach the LLM unmodified."
                            ),
                            evidence=(f"arg '{arg_name}' type=string, no pattern/enum/maxLength"),
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
                        f"All prompt arguments across "
                        f"{len(snapshot.prompts)} prompt(s) have input constraints."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
