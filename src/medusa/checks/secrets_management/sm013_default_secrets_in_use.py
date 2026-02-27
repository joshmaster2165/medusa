"""SM013: Default Secrets in Use.

Detects MCP servers that are using default secrets, example tokens, or placeholder credentials
that were included in documentation, sample configurations, or initial setup scripts. Default
secrets are publicly known and provide trivial unauthorized access.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Well-known default/example secrets
_DEFAULT_SECRETS = {
    "password",
    "password123",
    "password1",
    "changeme",
    "change_me",
    "secret",
    "mysecret",
    "my_secret",
    "admin",
    "admin123",
    "test",
    "testpassword",
    "test123",
    "example",
    "default",
    "letmein",
    "welcome",
    "qwerty",
    "123456",
    "1234567890",
    "hunter2",
    "abc123",
    "passw0rd",
    "p@ssword",
    "p@ssw0rd",
}
_DEFAULT_SECRET_RE = re.compile(
    r"\b(your[_-]?(api[_-]?key|token|secret|password)|<(api[_-]?key|token|secret)>|"
    r"xxx+|abc123|changeme|password123)\b",
    re.IGNORECASE,
)
_SECRET_KEY_RE = re.compile(r"(password|passwd|secret|api[_-]?key|token|credential)", re.IGNORECASE)


class DefaultSecretsInUseCheck(BaseCheck):
    """Default Secrets in Use."""

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
        for var, val in snapshot.env.items():
            targets.append((f"env.{var}", val))

        for location, value in targets:
            leaf = location.split(".")[-1].split("[")[0]
            if not _SECRET_KEY_RE.search(leaf):
                continue
            if value.lower() in _DEFAULT_SECRETS or _DEFAULT_SECRET_RE.search(value):
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
                            f"Default/example secret value detected at '{location}' for server "
                            f"'{snapshot.server_name}'. Default secrets must be replaced."
                        ),
                        evidence=f"{location}: {value[:20]}",
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
                        f"No default secrets detected for server '{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings
