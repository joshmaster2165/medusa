"""SM003: Secrets in Version Control.

Detects MCP server repositories that contain secrets committed to version control history. Even
if secrets are removed from current files, they persist in the git history and can be extracted
by anyone with repository access.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Look for references to .git paths or gitignore mentions in config
_VCS_RE = re.compile(r"(\.git/|\.gitignore|\.env\.git|secrets\.ya?ml)", re.IGNORECASE)


class SecretsInVersionControlCheck(BaseCheck):
    """Secrets in Version Control."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        targets: list[tuple[str, str]] = []
        if snapshot.config_raw:
            targets.extend(_flatten_config(snapshot.config_raw))
        for i, arg in enumerate(snapshot.args):
            targets.append((f"args[{i}]", arg))

        for location, value in targets:
            if _VCS_RE.search(value):
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="config",
                        resource_name=location,
                        status_extended=(
                            f"Version control path reference detected at '{location}' for server "
                            f"'{snapshot.server_name}'. Secrets may be committed to VCS."
                        ),
                        evidence=f"VCS reference: {value[:60]}",
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
                    resource_type="config",
                    resource_name=snapshot.config_file_path or "config",
                    status_extended=(
                        f"No version control secret references detected for server "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings
