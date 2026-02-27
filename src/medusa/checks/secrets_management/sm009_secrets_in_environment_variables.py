"""SM009: Secrets in Environment Variables.

Detects MCP servers that rely solely on environment variables for secret storage without
additional protection. While better than hardcoding, environment variables are accessible to all
processes running as the same user and are often logged or exposed through process listings and
debug endpoints.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _redact
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

_SECRET_ENV_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|auth[_-]?key)",
    re.IGNORECASE,
)


class SecretsInEnvironmentVariablesCheck(BaseCheck):
    """Secrets in Environment Variables."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if not snapshot.env:
            return []

        findings: list[Finding] = []
        for var, value in snapshot.env.items():
            if not value or len(value) < 4:
                continue
            if _SECRET_ENV_RE.search(var):
                findings.append(
                    Finding(
                        check_id=meta.check_id,
                        check_title=meta.title,
                        status=Status.FAIL,
                        severity=meta.severity,
                        server_name=snapshot.server_name,
                        server_transport=snapshot.transport_type,
                        resource_type="env",
                        resource_name=f"env.{var}",
                        status_extended=(
                            f"Secret-like environment variable '{var}' detected for server "
                            f"'{snapshot.server_name}'. Use a secrets manager instead."
                        ),
                        evidence=f"{var}={_redact(value)}",
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
                    resource_type="env",
                    resource_name=snapshot.config_file_path or "env",
                    status_extended=(
                        f"No secret-like environment variables detected for server "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings
