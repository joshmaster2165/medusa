"""DP033: Single-Tool Exfiltration Channel.

Detects tools that have BOTH data-source parameters (file, path, query,
content) AND data-sink parameters (url, webhook, endpoint, email) in
the same input schema. This combination enables data exfiltration through
a single tool invocation without needing to chain multiple tools.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SOURCE_PARAMS: set[str] = {
    "file",
    "path",
    "data",
    "content",
    "query",
    "source",
    "database",
    "input",
    "body",
    "payload",
    "record",
    "document",
    "table",
    "filepath",
    "filename",
    "directory",
    "text",
}

_SINK_PARAMS: set[str] = {
    "url",
    "webhook",
    "endpoint",
    "callback",
    "email",
    "recipient",
    "destination",
    "target_url",
    "remote",
    "host",
    "forward_to",
    "send_to",
    "webhook_url",
    "callback_url",
    "notify_url",
    "upload_url",
}


class SingleToolExfilChannelCheck(BaseCheck):
    """Single-Tool Exfiltration Channel."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            param_names = {p.lower() for p in properties}
            sources = param_names & _SOURCE_PARAMS
            sinks = param_names & _SINK_PARAMS

            if sources and sinks:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="tool",
                        resource_name=tool_name,
                        status_extended=(
                            f"Tool '{tool_name}' has both data-source "
                            f"params ({', '.join(sorted(sources))}) and "
                            f"data-sink params ({', '.join(sorted(sinks))}). "
                            f"This enables exfiltration in a single call."
                        ),
                        evidence=(f"source_params={sorted(sources)}, sink_params={sorted(sinks)}"),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings and snapshot.tools:
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
                        f"No single-tool exfiltration channels detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
