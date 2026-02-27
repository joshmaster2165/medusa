"""TS006: Weak TLS Cipher Suites.

Detects MCP servers configured with weak or deprecated TLS cipher suites. Weak ciphers such as
RC4, DES, 3DES, and export-grade ciphers can be broken by modern attacks, compromising the
confidentiality of encrypted communications.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.patterns.transport import WEAK_CIPHER_PATTERNS

_HTTP_TRANSPORTS = {"http", "sse"}
_CIPHER_KEYS = {"ciphers", "cipher_suites", "cipher_list", "tls_ciphers", "ssl_ciphers"}


def _walk_config_for_ciphers(config: dict, depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    hits: list[str] = []
    for k, v in config.items():
        if k.lower() in _CIPHER_KEYS and isinstance(v, str):
            hits.append(v)
        elif k.lower() in _CIPHER_KEYS and isinstance(v, list):
            hits.extend(str(c) for c in v)
        if isinstance(v, dict):
            hits.extend(_walk_config_for_ciphers(v, depth + 1))
    return hits


class WeakCipherSuitesCheck(BaseCheck):
    """Weak TLS Cipher Suites."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        cipher_values = _walk_config_for_ciphers(snapshot.config_raw or {})
        if not cipher_values:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="tls.ciphers",
                    status_extended=(
                        f"Server '{snapshot.server_name}' has no explicit cipher configuration "
                        f"(using defaults)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        weak_found: list[str] = []
        for cipher_str in cipher_values:
            for pattern in WEAK_CIPHER_PATTERNS:
                if pattern.search(cipher_str):
                    weak_found.append(cipher_str[:60])
                    break
        if weak_found:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name="tls.ciphers",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses weak TLS cipher suites: "
                        f"{'; '.join(weak_found[:3])}."
                    ),
                    evidence=f"Weak ciphers: {weak_found[:3]}",
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
                resource_name="tls.ciphers",
                status_extended=(f"Server '{snapshot.server_name}' cipher suites appear strong."),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
