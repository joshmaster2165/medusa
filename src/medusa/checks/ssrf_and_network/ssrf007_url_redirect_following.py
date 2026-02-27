"""SSRF-007: Uncontrolled URL Redirect Following.

Checks server config for redirect control settings. Absence of redirect
limits means HTTP redirects are followed without re-validating the target,
enabling SSRF bypass via open redirectors.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_REDIRECT_CONTROL_KEYS = {
    "follow_redirects",
    "redirect_follow",
    "max_redirects",
    "allow_redirects",
    "redirect_limit",
    "redirect_policy",
    "follow_redirect",
}


class UrlRedirectFollowingCheck(BaseCheck):
    """Detect missing redirect-following controls in server configuration."""

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

        has_control = any(k in combined for k in _REDIRECT_CONTROL_KEYS)

        if not has_control:
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
                        "No redirect-following control configuration detected. "
                        "HTTP redirects may be followed without re-validating the "
                        "redirect target, enabling SSRF bypass via open redirectors."
                    ),
                    evidence="No max_redirects or follow_redirects config keys found.",
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
                    status_extended="Redirect-following control configuration detected.",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
