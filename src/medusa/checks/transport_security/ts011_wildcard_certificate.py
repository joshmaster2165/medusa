"""TS011: Wildcard Certificate Usage.

Detects MCP servers using wildcard TLS certificates (*.example.com). Wildcard certificates cover
all subdomains, meaning a private key compromise on any subdomain's server exposes all
subdomains to impersonation.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_WILDCARD_PATTERN = re.compile(r"\*\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}")
_CERT_KEYS = {
    "certificate",
    "cert",
    "tls_cert",
    "ssl_cert",
    "server_cert",
    "cert_file",
    "cert_name",
}


def _find_wildcard_cert(config: dict, depth: int = 0) -> str | None:
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in _CERT_KEYS and isinstance(v, str):
            if _WILDCARD_PATTERN.search(v):
                return f"Wildcard cert at '{k}': {v[:40]}"
        if k.lower() in {"common_name", "san", "subject_alt_names"} and isinstance(v, str):
            if v.startswith("*."):
                return f"Wildcard CN/SAN at '{k}': {v}"
        if isinstance(v, dict):
            result = _find_wildcard_cert(v, depth + 1)
            if result:
                return result
    return None


class WildcardCertificateCheck(BaseCheck):
    """Wildcard Certificate Usage."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence = _find_wildcard_cert(snapshot.config_raw or {})
        if evidence:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="tls.certificate",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses a wildcard certificate. "
                        f"A key compromise on any subdomain exposes all subdomains."
                    ),
                    evidence=evidence,
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="config",
                resource_name="tls.certificate",
                status_extended=(
                    f"Server '{snapshot.server_name}' does not appear to use wildcard certificates."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
