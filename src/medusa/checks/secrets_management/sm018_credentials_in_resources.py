"""SM018: Credentials in Resource Descriptions.

Detects API keys, tokens, and secrets exposed in MCP resource
descriptions and URIs. Also checks for credentials embedded in URL
authority sections (e.g., ://user:password@host).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Known secret prefixes (case-sensitive) -- same set as sm017.
_SECRET_PREFIXES: list[str] = [
    "sk-",
    "pk_live_",
    "pk_test_",
    "Bearer ",
    "AKIA",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "glpat-",
    "pypi-",
    "npm_",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "sq0atp-",
    "EAACEdEose0cBA",
    "key-",
    "SG.",
    "xkeysib-",
]

# Credential assignment patterns.
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?:password|token|secret|api_key|apikey)=(\S+)",
    re.IGNORECASE,
)

# URL with embedded credentials: ://user:password@host
_URL_CREDENTIALS_RE = re.compile(
    r"://([^:/@\s]+):([^@/\s]+)@",
)


class CredentialsInResourcesCheck(BaseCheck):
    """Credentials in Resource Descriptions."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.resources:
            return findings

        for resource in snapshot.resources:
            resource_name = resource.get("name", resource.get("uri", "unknown"))
            description = resource.get("description", "")
            uri = resource.get("uri", "")

            # Scan both description and URI for secret prefixes
            for text, text_label in [
                (description, "description"),
                (uri, "URI"),
            ]:
                if not text:
                    continue
                self._check_secret_prefixes(
                    text, text_label, resource_name, meta, snapshot, findings,
                )
                self._check_credential_assignments(
                    text, text_label, resource_name, meta, snapshot, findings,
                )

            # Check URI specifically for embedded credentials
            if uri:
                match = _URL_CREDENTIALS_RE.search(uri)
                if match:
                    username = match.group(1)
                    password = match.group(2)
                    # Mask the password
                    masked_password = password[:2] + "*" * max(0, len(password) - 2)
                    findings.append(Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=resource_name,
                        status_extended=(
                            f"Resource '{resource_name}' URI contains embedded credentials "
                            f"in the format '://user:password@host'."
                        ),
                        evidence=f"Username: {username}, Password: {masked_password}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    ))

        if not findings:
            findings.append(Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="server",
                resource_name=snapshot.server_name,
                status_extended="No credentials detected in resource descriptions or URIs.",
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            ))
        return findings

    def _check_secret_prefixes(
        self,
        text: str,
        text_label: str,
        resource_name: str,
        meta: CheckMetadata,
        snapshot: ServerSnapshot,
        findings: list[Finding],
    ) -> None:
        for prefix in _SECRET_PREFIXES:
            idx = text.find(prefix)
            if idx != -1:
                start = max(0, idx - 10)
                end = min(len(text), idx + len(prefix) + 20)
                snippet = text[start:end]
                findings.append(Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="resource",
                    resource_name=resource_name,
                    status_extended=(
                        f"Resource '{resource_name}' {text_label} contains a string "
                        f"matching known secret prefix '{prefix}'."
                    ),
                    evidence=f"Snippet: ...{snippet}...",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                ))
                break  # One prefix finding per text field

    def _check_credential_assignments(
        self,
        text: str,
        text_label: str,
        resource_name: str,
        meta: CheckMetadata,
        snapshot: ServerSnapshot,
        findings: list[Finding],
    ) -> None:
        matches = _CREDENTIAL_ASSIGNMENT_RE.findall(text)
        for match_value in matches:
            if len(match_value) >= 6:
                findings.append(Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="resource",
                    resource_name=resource_name,
                    status_extended=(
                        f"Resource '{resource_name}' {text_label} contains a credential "
                        f"assignment pattern with a value of length {len(match_value)}."
                    ),
                    evidence=f"Pattern match: <key>={match_value[:4]}****",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                ))
                break  # One assignment finding per text field
