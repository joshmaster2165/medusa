"""TS018: Proxy Without TLS.

Detects MCP server proxy configurations that do not use TLS encryption. Proxies without TLS
decrypt and re-encrypt traffic, creating a plaintext exposure point. Unencrypted proxy
connections expose all traffic to interception at the proxy hop.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_HTTP_TRANSPORTS = {"http", "sse"}
_PROXY_KEYS = {
    "proxy",
    "http_proxy",
    "https_proxy",
    "proxy_url",
    "proxy_host",
    "socks_proxy",
    "socks5_proxy",
}
_SECURE_PROXY_SCHEMES = {"https://", "socks5s://", "socks5h://"}
_INSECURE_PROXY_SCHEMES = {"http://", "socks4://", "socks5://"}


def _walk_config(config: dict, keys: set[str], depth: int = 0) -> bool:
    if depth > 10:
        return False
    for k, v in config.items():
        if k.lower() in keys:
            return True
        if isinstance(v, dict) and _walk_config(v, keys, depth + 1):
            return True
    return False


def _find_insecure_proxy(config: dict, depth: int = 0) -> str | None:
    """Return evidence string if an insecure proxy URL is found."""
    if depth > 10:
        return None
    for k, v in config.items():
        if k.lower() in _PROXY_KEYS and isinstance(v, str):
            if any(v.lower().startswith(scheme) for scheme in _INSECURE_PROXY_SCHEMES):
                return f"'{k}' = '{v}'"
        if isinstance(v, dict):
            result = _find_insecure_proxy(v, depth + 1)
            if result:
                return result
    return None


def _has_proxy_without_https(env: dict[str, str]) -> str | None:
    """Check environment for HTTP proxy settings without TLS."""
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        v = env.get(k, "")
        if v and any(v.lower().startswith(s) for s in _INSECURE_PROXY_SCHEMES):
            return f"{k}={v}"
    return None


class ProxyWithoutTlsCheck(BaseCheck):
    """Proxy Without TLS."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if snapshot.transport_type not in _HTTP_TRANSPORTS:
            return []
        evidence: str | None = _find_insecure_proxy(snapshot.config_raw or {})
        if not evidence:
            evidence = _has_proxy_without_https(snapshot.env or {})
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
                    resource_name="proxy.tls",
                    status_extended=(
                        f"Server '{snapshot.server_name}' uses an unencrypted proxy connection. "
                        f"All traffic through the proxy is exposed in plaintext."
                    ),
                    evidence=evidence,
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]
        has_proxy = _walk_config(snapshot.config_raw or {}, _PROXY_KEYS)
        if not has_proxy:
            # No proxy configured; not applicable
            return []
        return [
            Finding(
                check_id=meta.check_id,
                check_title=meta.title,
                status=Status.PASS,
                severity=meta.severity,
                server_name=snapshot.server_name,
                server_transport=snapshot.transport_type,
                resource_type="config",
                resource_name="proxy.tls",
                status_extended=(
                    f"Server '{snapshot.server_name}' proxy configuration uses TLS encryption."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
