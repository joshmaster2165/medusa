"""SC012: Insecure HTTP Transport.

Detects HTTP (non-HTTPS) transport URLs which expose MCP client-server
communications to man-in-the-middle attacks. All non-local HTTP connections
should use TLS to protect tool invocations, credentials, and data in transit.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Localhost patterns that are acceptable for development.
_LOCALHOST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^http://localhost\b", re.IGNORECASE),
    re.compile(r"^http://127\.0\.0\.1\b", re.IGNORECASE),
    re.compile(r"^http://\[::1\]", re.IGNORECASE),
    re.compile(r"^http://0\.0\.0\.0\b", re.IGNORECASE),
]


def _is_localhost(url: str) -> bool:
    """Check if a URL points to a localhost address."""
    return any(pattern.match(url) for pattern in _LOCALHOST_PATTERNS)


class InsecureHttpTransportCheck(BaseCheck):
    """Insecure HTTP Transport."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        # Only applicable to HTTP transport types.
        if snapshot.transport_type not in ("http", "sse"):
            return findings

        if not snapshot.transport_url:
            return findings

        url = snapshot.transport_url.strip()

        # Check for plain HTTP (non-HTTPS).
        if url.lower().startswith("http://"):
            if _is_localhost(url):
                # Localhost is acceptable for development.
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
                            f"Server '{snapshot.server_name}' uses plain HTTP but "
                            f"connects to localhost ({url}), which is acceptable "
                            f"for local development."
                        ),
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
            else:
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
                            f"Server '{snapshot.server_name}' uses insecure HTTP "
                            f"transport ({url}). Communications are unencrypted and "
                            f"vulnerable to man-in-the-middle attacks. Tool invocations, "
                            f"credentials, and data are exposed in transit."
                        ),
                        evidence=f"transport_url={url}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )
        else:
            # HTTPS or other secure scheme.
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
                        f"Server '{snapshot.server_name}' uses secure transport ({url})."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
