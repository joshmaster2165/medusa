"""TF-004: Sampling/CreateMessage Injection Flow.

Detects when a server advertises the MCP sampling capability (createMessage)
alongside tools that accept user-controlled text parameters, creating a
cross-model prompt injection flow.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_TEXT_PARAMS: set[str] = {
    "message",
    "text",
    "content",
    "prompt",
    "query",
    "input",
    "body",
    "data",
    "description",
}


class SamplingInjectionFlowCheck(BaseCheck):
    """Detect sampling/createMessage injection flows."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        has_sampling = snapshot.capabilities.get("sampling") is not None

        if not has_sampling:
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
                        "Server does not advertise sampling capability. "
                        "No createMessage injection flow is possible."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        # Find tools with user-text parameters
        text_tools: list[str] = []
        for tool in snapshot.tools:
            props = tool.get("inputSchema", {}).get("properties", {})
            param_names_lower = {p.lower() for p in props}
            if param_names_lower & _TEXT_PARAMS:
                text_tools.append(tool.get("name", "<unnamed>"))

        if text_tools:
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
                        f"Server advertises sampling capability and has "
                        f"{len(text_tools)} tool(s) accepting user text. "
                        f"An attacker could inject content through these "
                        f"tools that gets forwarded via createMessage to "
                        f"other LLMs."
                    ),
                    evidence=f"sampling=enabled, text_tools={text_tools[:10]}",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
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
                        f"Server advertises sampling capability but no "
                        f"tools accept user-controlled text parameters "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
