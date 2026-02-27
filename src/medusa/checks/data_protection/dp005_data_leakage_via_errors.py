"""DP005: Data Leakage via Error Messages.

Detects MCP servers that expose sensitive data in error responses. Stack traces, database
connection strings, internal paths, and debug information returned in error messages can reveal
implementation details and secrets to untrusted LLM clients.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_ERROR_KEYWORDS = re.compile(
    r"(stack.?trace|stacktrace|debug|traceback|exception|internal.?error|"
    r"verbose.?error|error.?detail|show.?error|expose.?error|dump.?error)",
    re.IGNORECASE,
)

_DEBUG_CONFIG_KEYS: set[str] = {
    "debug",
    "verbose_errors",
    "stacktrace",
    "show_stacktrace",
    "debug_mode",
    "verbose",
    "expose_errors",
    "detailed_errors",
}


def _walk_config_for_debug(config: Any, _depth: int = 0) -> list[tuple[str, object]]:
    hits: list[tuple[str, object]] = []
    if _depth > 10:
        return hits
    if isinstance(config, dict):
        for key, value in config.items():
            if isinstance(key, str) and key.lower() in _DEBUG_CONFIG_KEYS:
                if isinstance(value, bool) and value:
                    hits.append((key, value))
                elif isinstance(value, str) and value.lower() in (
                    "true",
                    "1",
                    "yes",
                    "enabled",
                    "on",
                ):
                    hits.append((key, value))
            if isinstance(value, dict):
                hits.extend(_walk_config_for_debug(value, _depth + 1))
    return hits


class DataLeakageViaErrorsCheck(BaseCheck):
    """Data Leakage via Error Messages."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        has_content = bool(snapshot.tools or snapshot.config_raw)
        if not has_content:
            return findings

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            desc = tool.get("description") or ""
            matches = _ERROR_KEYWORDS.findall(desc)
            if matches:
                match_str = ", ".join(dict.fromkeys(m.lower() for m in matches))
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
                        status_extended=f"Tool '{tool_name}' references error/debug keywords:"
                        f"{match_str}",
                        evidence=f"keywords={match_str}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if snapshot.config_raw:
            debug_hits = _walk_config_for_debug(snapshot.config_raw)
            for key, value in debug_hits:
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="config",
                        resource_name=key,
                        status_extended=f"Config key '{key}' enables debug/error exposure"
                        f"(value={value})",
                        evidence=f"{key}={value}",
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
                    status_extended="No data leakage via error messages detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
