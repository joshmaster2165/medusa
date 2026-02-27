"""DP011: Excessive Logging of PII.

Detects MCP server configurations that combine verbose logging settings with tools that handle PII
parameters, creating a risk of personal data being written to log files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_VERBOSE_LOG_KEYS: set[str] = {"debug", "log_level", "verbose", "log_bodies", "trace"}
_PII_PARAM_NAMES: set[str] = {
    "name",
    "email",
    "phone",
    "address",
    "ssn",
    "date_of_birth",
    "age",
    "password",
    "credit_card",
    "ip_address",
    "username",
}


def _has_verbose_logging(config: Any, _depth: int = 0) -> bool:
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key, val in config.items():
            k = key.lower() if isinstance(key, str) else ""
            if k in _VERBOSE_LOG_KEYS:
                sv = str(val).lower()
                if sv in ("debug", "trace", "true", "1", "yes", "verbose"):
                    return True
            if isinstance(val, dict) and _has_verbose_logging(val, _depth + 1):
                return True
    return False


class ExcessiveLoggingOfPiiCheck(BaseCheck):
    """Excessive Logging of PII."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        verbose = _has_verbose_logging(snapshot.config_raw) if snapshot.config_raw else False
        if not verbose:
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
                    status_extended="No verbose logging with PII exposure risk detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        for tool in snapshot.tools:
            tool_name = tool.get("name", "<unnamed>")
            schema = tool.get("inputSchema") or {}
            props = schema.get("properties") or {}
            pii_params = [p for p in props if p.lower() in _PII_PARAM_NAMES]
            if pii_params:
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
                        status_extended=f"Verbose logging enabled with PII params in tool"
                        f"'{tool_name}': {', '.join(pii_params)}",
                        evidence=f"pii_params={', '.join(pii_params)}",
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
                    status_extended="Verbose logging enabled but no PII-named parameters detected"
                    "in tools.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
