"""TP046: Shadow Tool Capability Expansion.

Detects tools with safe-sounding read-only name prefixes (read_, get_, list_,
search_, etc.) but whose schemas contain dangerous parameters like shell
commands, webhooks, external URLs, or credentials.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SAFE_TOOL_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"^(read|get|list|search|find|view|show|fetch|browse|inspect)"
        r"[-_]",
        re.IGNORECASE,
    ),
]

_DANGEROUS_PARAM_NAMES: set[str] = {
    # Shell execution
    "command",
    "cmd",
    "shell",
    "exec",
    "execute",
    "run",
    "script",
    "bash",
    "sh",
    "subprocess",
    "system",
    "eval",
    # Exfiltration
    "callback_url",
    "webhook",
    "webhook_url",
    "send_to",
    "remote_endpoint",
    "remote_url",
    "external_url",
    "forward_to",
    "notify_url",
    "upload_url",
    # Credentials
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
    "credential",
    "auth_token",
    "access_key",
}


class ShadowToolCapabilityExpansionCheck(BaseCheck):
    """Shadow Tool Capability Expansion."""

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

            # Check if tool name matches safe patterns
            is_safe_name = any(p.match(tool_name) for p in _SAFE_TOOL_NAME_PATTERNS)
            if not is_safe_name:
                continue

            # Extract parameter names from schema
            schema = tool.get("inputSchema") or tool.get("parameters", {})
            properties = schema.get("properties", {})
            param_names = {k.lower() for k in properties}

            dangerous_found = param_names & _DANGEROUS_PARAM_NAMES
            if dangerous_found:
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
                            f"Tool '{tool_name}' has a safe read-only "
                            f"name prefix but contains dangerous "
                            f"parameters: "
                            f"{', '.join(sorted(dangerous_found))}. "
                            f"This may indicate a tool shadowing attack."
                        ),
                        evidence=(
                            f"safe_name={tool_name}, dangerous_params={sorted(dangerous_found)}"
                        ),
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
                        f"No safe-named tools with dangerous "
                        f"parameters detected across "
                        f"{len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
