"""CTX-001: Detect excessive tool/resource/prompt counts (over-sharing).

Flags MCP servers that expose more than a reasonable number of tools,
resources, or prompts, indicating a potential violation of the principle
of least privilege.

Thresholds:
- Tools: > 30
- Resources: > 50
- Prompts: > 20
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

TOOL_THRESHOLD = 30
RESOURCE_THRESHOLD = 50
PROMPT_THRESHOLD = 20


class ResourceOverSharingCheck(BaseCheck):
    """Check for excessive numbers of tools, resources, or prompts."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        tool_count = len(snapshot.tools)
        resource_count = len(snapshot.resources)
        prompt_count = len(snapshot.prompts)

        # Nothing to check if nothing is exposed
        if tool_count == 0 and resource_count == 0 and prompt_count == 0:
            return findings

        if tool_count > TOOL_THRESHOLD:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server exposes {tool_count} tools, exceeding the "
                        f"threshold of {TOOL_THRESHOLD}."
                    ),
                    evidence=f"tool_count={tool_count}, threshold={TOOL_THRESHOLD}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if resource_count > RESOURCE_THRESHOLD:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server exposes {resource_count} resources, exceeding "
                        f"the threshold of {RESOURCE_THRESHOLD}."
                    ),
                    evidence=(f"resource_count={resource_count}, threshold={RESOURCE_THRESHOLD}"),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        if prompt_count > PROMPT_THRESHOLD:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server exposes {prompt_count} prompts, exceeding "
                        f"the threshold of {PROMPT_THRESHOLD}."
                    ),
                    evidence=(f"prompt_count={prompt_count}, threshold={PROMPT_THRESHOLD}"),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        # Emit PASS if no thresholds were exceeded
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
                        f"Server exposes {tool_count} tool(s), "
                        f"{resource_count} resource(s), and "
                        f"{prompt_count} prompt(s) — within acceptable limits."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
