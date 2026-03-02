"""PMT-019: Excessive Prompt Argument Count.

Detects prompts with an excessive number of arguments (more than 10).
A large number of arguments increases the injection surface area and
makes it harder to validate and sanitize all inputs properly.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAX_ARGUMENTS = 10


class ExcessivePromptArgumentsCheck(BaseCheck):
    """Excessive Prompt Argument Count."""

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
            arguments = prompt.get("arguments") or []
            arg_count = len(arguments)

            if arg_count > _MAX_ARGUMENTS:
                arg_names = [a.get("name", "?") for a in arguments]
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
                            f"Prompt '{prompt_name}' has {arg_count} arguments "
                            f"(threshold: {_MAX_ARGUMENTS}). Excessive arguments "
                            f"increase injection surface area."
                        ),
                        evidence=(
                            f"Argument count: {arg_count}; "
                            f"Names: {', '.join(arg_names[:5])}"
                            f"{'...' if arg_count > 5 else ''}"
                        ),
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
                        f"All prompts have {_MAX_ARGUMENTS} or fewer arguments "
                        f"across {len(snapshot.prompts)} prompt(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
