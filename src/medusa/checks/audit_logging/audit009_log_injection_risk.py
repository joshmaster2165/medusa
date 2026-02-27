"""AUDIT009: Log Injection Risk.

Detects MCP server logging patterns that write user-supplied input to log files without
sanitization. Unsanitized log entries enable log injection attacks that corrupt log integrity.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_LOG_PARAM_NAMES: set[str] = {
    "log",
    "log_message",
    "message",
    "comment",
    "note",
    "description",
    "log_entry",
    "log_data",
    "audit_message",
    "log_text",
}


class LogInjectionRiskCheck(BaseCheck):
    """Log Injection Risk."""

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
            tool_name = tool.get("name", "<unnamed>")
            schema = tool.get("inputSchema") or {}
            props = schema.get("properties") or {}
            for param_name, param_def in props.items():
                if param_name.lower() not in _LOG_PARAM_NAMES:
                    continue
                p_type = param_def.get("type", "")
                if p_type != "string":
                    continue
                has_pattern = bool(param_def.get("pattern"))
                has_enum = bool(param_def.get("enum"))
                if not has_pattern and not has_enum:
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
                                f"Tool '{tool_name}' param '{param_name}' is a log-destined "
                                f"string without pattern or enum constraint — log injection risk."
                            ),
                            evidence=f"tool={tool_name}, param={param_name}",
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
                    status_extended=f"No log injection risks detected across"
                    f"{len(snapshot.tools)} tool(s).",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
