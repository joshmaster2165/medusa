"""SSRF-016: Missing Request Timeout.

Checks server configuration for timeout settings. Absence indicates network
requests may hang indefinitely, enabling resource exhaustion via slowloris-style attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_TIMEOUT_KEYS = {
    "timeout",
    "request_timeout",
    "connect_timeout",
    "read_timeout",
    "write_timeout",
    "socket_timeout",
    "http_timeout",
    "timeout_ms",
    "timeout_seconds",
    "connection_timeout",
}


class MissingRequestTimeoutCheck(BaseCheck):
    """Check for absence of request timeout configuration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        config_str = str(snapshot.config_raw).lower() if snapshot.config_raw else ""
        args_str = " ".join(snapshot.args).lower()
        combined = f"{config_str} {args_str}"

        has_timeout = any(k in combined for k in _TIMEOUT_KEYS)

        if not has_timeout:
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
                        "No request timeout configuration detected. Network "
                        "requests may hang indefinitely, enabling resource "
                        "exhaustion attacks."
                    ),
                    evidence="No timeout/request_timeout/connect_timeout keys found in config.",
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
                    status_extended="Request timeout configuration detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
