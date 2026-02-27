"""TS-001: Detect unencrypted transport (HTTP instead of HTTPS).

Flags MCP servers whose transport URL or configuration uses plain HTTP,
exposing all traffic to interception and tampering.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}


class UnencryptedTransportCheck(BaseCheck):
    """Check for unencrypted HTTP transport."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []

        # Check transport_url
        if snapshot.transport_url:
            parsed = urlparse(snapshot.transport_url)
            if parsed.scheme == "http":
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
                            f"Server '{snapshot.server_name}' uses unencrypted "
                            f"HTTP transport ({snapshot.transport_url}). All data "
                            f"including tool calls and responses is transmitted "
                            f"in cleartext."
                        ),
                        evidence=f"transport_url = {snapshot.transport_url}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        # Check config_raw for http:// URLs
        if not findings and snapshot.config_raw:
            for key, value in snapshot.config_raw.items():
                if isinstance(value, str) and value.startswith("http://"):
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="config",
                            resource_name=f"config.{key}",
                            status_extended=(
                                f"Configuration key '{key}' for server "
                                f"'{snapshot.server_name}' contains an "
                                f"unencrypted HTTP URL."
                            ),
                            evidence=f"{key} = {value}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )
                    break

        # Check proxy env vars
        if not findings:
            for env_key, env_value in snapshot.env.items():
                if env_key.lower() in ("http_proxy", "https_proxy") and env_value.startswith(
                    "http://"
                ):
                    findings.append(
                        Finding(
                            check_id=meta.check_id,
                            check_title=meta.title,
                            status=Status.FAIL,
                            severity=meta.severity,
                            server_name=snapshot.server_name,
                            server_transport=snapshot.transport_type,
                            resource_type="config",
                            resource_name=f"env.{env_key}",
                            status_extended=(
                                f"Proxy environment variable '{env_key}' uses "
                                f"unencrypted HTTP for server "
                                f"'{snapshot.server_name}'."
                            ),
                            evidence=f"{env_key} = {env_value}",
                            remediation=meta.remediation,
                            owasp_mcp=meta.owasp_mcp,
                        )
                    )
                    break

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
                        f"Server '{snapshot.server_name}' uses encrypted transport (HTTPS)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
