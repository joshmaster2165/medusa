"""RES-022: Sensitive File Extension Exposure.

Detects resources that expose files with sensitive extensions such as
private keys, certificates, password stores, and environment files.
Exposing these file types through MCP resources can lead to credential
theft and unauthorized system access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SENSITIVE_EXTENSIONS: set[str] = {
    ".env",
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".jks",
    ".keystore",
    ".cert",
    ".crt",
    ".csr",
    ".der",
    ".ssh",
    ".ppk",
    ".gpg",
    ".asc",
    ".kdbx",
    ".htpasswd",
    ".htaccess",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".pgpass",
    ".cnf",
}


def _extract_extensions(value: str) -> list[str]:
    """Extract file extensions from a URI or name string.

    Handles compound extensions like '.tar.gz' by checking each suffix
    and also checking the full compound suffix.
    """
    p = Path(value.split("?")[0].split("#")[0])  # strip query/fragment
    suffixes = p.suffixes  # e.g. ['.id_rsa', '.pub'] or ['.env']
    return [s.lower() for s in suffixes]


class SensitiveFileExtensionCheck(BaseCheck):
    """Sensitive File Extension Exposure."""

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
            uri = resource.get("uri", "")
            name = resource.get("name", "<unnamed>")

            # Check both URI and name for sensitive extensions
            all_extensions: list[str] = []
            all_extensions.extend(_extract_extensions(uri))
            all_extensions.extend(_extract_extensions(name))

            matched = [ext for ext in all_extensions if ext in _SENSITIVE_EXTENSIONS]

            if matched:
                unique_matched = sorted(set(matched))
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="resource",
                        resource_name=name,
                        status_extended=(
                            f"Resource '{name}' exposes a file with sensitive "
                            f"extension(s): {', '.join(unique_matched)}. "
                            f"URI: {uri}"
                        ),
                        evidence=f"Sensitive extensions: {', '.join(unique_matched)}",
                        remediation=meta.remediation,
                        owasp_mcp=meta.owasp_mcp,
                    )
                )

        if not findings:
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
                        f"No sensitive file extensions detected across "
                        f"{len(snapshot.resources)} resource(s)."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings
