"""PMT007: Excessive Prompt Arguments.

Detects MCP prompt definitions that accept an excessive number of arguments, creating a large
attack surface for injection through any of the argument slots. Prompts with many arguments are
harder to validate and more likely to have overlooked injection vectors.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAX_ARGS: int = 10


class ExcessivePromptArgumentsCheck(BaseCheck):
    """Excessive Prompt Arguments."""

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
            arg_count = len(arguments)

            if arg_count > _MAX_ARGS:
                arg_names = [a.get("name", "?") for a in arguments[:10]]
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
                            f"(threshold is {_MAX_ARGS}). Excessive arguments "
                            f"increase injection attack surface."
                        ),
                        evidence=(
                            f"{arg_count} arguments (threshold {_MAX_ARGS}). "
                            f"First 10: {', '.join(arg_names)}"
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
                        f"All {len(snapshot.prompts)} prompt(s) have "
                        f"{_MAX_ARGS} or fewer arguments."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
