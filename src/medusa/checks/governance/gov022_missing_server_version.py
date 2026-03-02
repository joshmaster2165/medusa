"""GOV022: Missing Server Version.

Detects servers that do not declare version information in server_info.
Without versioning, it is impossible to track security patches or known
vulnerabilities for deployed server instances.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_PLACEHOLDER_VERSIONS: set[str] = {
    "0.0.0",
    "dev",
    "latest",
    "unknown",
    "none",
    "n/a",
    "tbd",
    "0.0.0-dev",
    "0.0.1-snapshot",
    "snapshot",
}


class MissingServerVersionCheck(BaseCheck):
    """Missing Server Version."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.server_info:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(
                        snapshot.transport_type
                    ),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"has no server_info. Version "
                        f"information is not available."
                    ),
                    evidence="server_info=missing",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
            return findings

        version = snapshot.server_info.get("version", "")
        version_str = str(version).strip().lower()

        if not version_str:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(
                        snapshot.transport_type
                    ),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"does not declare a version in "
                        f"server_info."
                    ),
                    evidence="version=empty",
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        elif version_str in _PLACEHOLDER_VERSIONS:
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(
                        snapshot.transport_type
                    ),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"declares a placeholder version "
                        f"'{version}' instead of a real "
                        f"version number."
                    ),
                    evidence=(
                        f"version='{version}' "
                        f"(placeholder)"
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
                    status=Status.PASS,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=(
                        snapshot.transport_type
                    ),
                    resource_type="server",
                    resource_name=snapshot.server_name,
                    status_extended=(
                        f"Server '{snapshot.server_name}' "
                        f"declares version '{version}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
