"""CRED024: Credential Harvesting via Tool Input.

Detects tools that request credential-like inputs (password, api_key,
token, secret) in their parameters. Such tools may be designed to harvest
credentials from users or LLM agents, mapping to the Credential
Exfiltration TTP for token interception.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_CREDENTIAL_PARAMS: set[str] = {
    "password",
    "secret",
    "api_key",
    "apikey",
    "token",
    "private_key",
    "access_key",
    "secret_key",
    "auth_token",
    "credentials",
    "passphrase",
    "client_secret",
    "bearer_token",
    "session_token",
    "api_secret",
    "auth_key",
    "master_key",
    "encryption_key",
}

_CREDENTIAL_CONTEXT_WORDS: set[str] = {
    "password",
    "secret",
    "credential",
    "authenticate",
    "api key",
    "token",
    "private key",
    "passphrase",
    "authorization",
}


class CredentialHarvestingToolCheck(BaseCheck):
    """Credential Harvesting via Tool Input."""

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

            cred_params: list[str] = []
            for param_name, param_def in properties.items():
                param_lower = param_name.lower()
                if param_lower in _CREDENTIAL_PARAMS:
                    cred_params.append(param_name)
                    continue
                # Check partial matches with description context
                if not isinstance(param_def, dict):
                    continue
                desc = (param_def.get("description", "") or "").lower()
                if any(w in desc for w in _CREDENTIAL_CONTEXT_WORDS):
                    # Only flag if param name also hints at credentials
                    if any(
                        part in param_lower
                        for part in ("pass", "key", "secret", "token", "cred", "auth")
                    ):
                        cred_params.append(param_name)

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
                            f"Tool '{tool_name}' requests credential-like "
                            f"inputs: {', '.join(cred_params)}. This may "
                            f"be a credential harvesting vector."
                        ),
                        evidence=f"credential_params={cred_params}",
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
                        f"No credential harvesting tools detected "
                        f"across {len(snapshot.tools)} tool(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
