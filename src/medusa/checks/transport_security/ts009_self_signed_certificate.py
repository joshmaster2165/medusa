"""TS009: Self-Signed Certificate Usage.

Detects MCP servers using self-signed TLS certificates. Self-signed certificates cannot be
verified against a trusted certificate authority chain, requiring clients to disable certificate
validation and making them vulnerable to man-in-the-middle attacks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_SELF_SIGNED_KEYS = {
    "self_signed",
    "selfsigned",
    "skip_verify",
    "skipverify",
    "insecure_skip_verify",
    "no_verify",
    "allow_self_signed",
}
_DISABLE_VERIFY_VALUES = {"false", "0", "no", "disabled"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            if isinstance(v, bool) and v:
                return True
            if isinstance(v, str) and v.lower() in ("true", "1", "yes"):
                return True
        if k.lower() in {"verify", "ssl_verify", "tls_verify"} and isinstance(v, (str, bool)):
            val = str(v).lower()
            if val in _DISABLE_VERIFY_VALUES:
                return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


class SelfSignedCertificateCheck(BaseCheck):
    """Self-Signed Certificate Usage."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        has_self_signed = _walk_config(snapshot.config_raw or {}, _SELF_SIGNED_KEYS)
        if has_self_signed:
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
                        f"Server '{snapshot.server_name}' is configured to accept or use"
                        f"self-signed "
                        f"certificates. Certificate validation is bypassed, enabling MITM attacks."
                    ),
                    evidence="self_signed/skip_verify/insecure_skip_verify configuration detected",
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
                    f"Server '{snapshot.server_name}' does not appear to use self-signed"
                    f"certificates."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
