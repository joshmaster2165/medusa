"""AUTH030: Credential Parameters over Insecure Transport.

Detects tools that accept credential-like parameters such as password, token,
api_key, and secret while the server uses insecure HTTP transport (not HTTPS).
Transmitting credentials over plaintext HTTP enables man-in-the-middle attacks
and credential interception.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CREDENTIAL_PARAM_NAMES: set[str] = {
    "password",
    "token",
    "api_key",
    "secret",
    "credential",
    "credentials",
    "auth_token",
    "access_token",
    "private_key",
    "passphrase",
    "secret_key",
    "client_secret",
    "api_secret",
}


class CredentialParamsInsecureTransportCheck(BaseCheck):
    """Credential Parameters over Insecure Transport."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.tools:
            return findings

        transport_url = snapshot.transport_url or ""

        # If transport is not insecure HTTP, emit a PASS and return early.
        if not transport_url.startswith("http://"):
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
                        f"No credential parameters over insecure transport "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        # Transport is insecure HTTP — check each tool for credential params.
        for tool in snapshot.tools:
            tool_name: str = tool.get("name", "<unnamed>")
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {}) if input_schema else {}

            cred_params: list[str] = [
                param_name
                for param_name in properties
                if param_name.lower() in _CREDENTIAL_PARAM_NAMES
            ]

            if cred_params:
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
                            f"Tool '{tool_name}' accepts credential parameters "
                            f"({', '.join(cred_params[:3])}) over insecure HTTP "
                            f"transport. Credentials may be intercepted in transit."
                        ),
                        evidence=(
                            f"tool={tool_name}, credential_params={cred_params}, "
                            f"transport={transport_url}"
                        ),
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
                    status_extended=(
                        f"No credential parameters over insecure transport "
                        f"detected across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
