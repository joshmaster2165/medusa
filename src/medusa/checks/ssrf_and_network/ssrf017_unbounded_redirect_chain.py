"""SSRF-017: Unbounded Redirect Chain.

Checks server configuration for explicit max_redirects limits. Absence means
redirect chains are unbounded, enabling infinite loops and redirect-chain SSRF.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_MAX_REDIRECT_KEYS = {
    "max_redirects",
    "redirect_limit",
    "max_redirect_count",
    "redirect_max",
    "max_redirect",
    "follow_redirects",
}


class UnboundedRedirectChainCheck(BaseCheck):
    """Check for absence of redirect chain limit configuration."""

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

        has_limit = any(k in combined for k in _MAX_REDIRECT_KEYS)

        if not has_limit:
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
                        "No max_redirects limit configuration detected. HTTP "
                        "redirect chains are unbounded, enabling infinite loops "
                        "and redirect-based SSRF attacks."
                    ),
                    evidence="No max_redirects/redirect_limit keys found in server config.",
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
                    status_extended="Redirect chain limit configuration detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
