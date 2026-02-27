"""SM001: Plaintext Secrets in Configuration.

Detects MCP server configuration files that contain secrets such as API keys, database
passwords, encryption keys, and OAuth tokens stored in plaintext without encryption.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import (
    _flatten_config,
    _redact,
)
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Keys that are likely to contain secret values
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|auth)",
    re.IGNORECASE,
)
# Values that look like real secrets (non-trivial, non-placeholder)
_PLACEHOLDER_RE = re.compile(
    r"^(your[-_]?.*|<.*>|\$\{.*\}|%.*%|xxx+|changeme|todo|example|none|null|true|false)$",
    re.IGNORECASE,
)


class PlaintextSecretsInConfigCheck(BaseCheck):
    """Plaintext Secrets in Configuration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if not snapshot.config_raw:
            return []

        for key, value in _flatten_config(snapshot.config_raw):
            leaf_key = key.split(".")[-1].split("[")[0]
            if not _SECRET_KEY_RE.search(leaf_key):
                continue
            if not value or len(value) < 4:
                continue
            if _PLACEHOLDER_RE.match(value):
                continue
            findings.append(
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name=key,
                    status_extended=(
                        f"Plaintext secret detected at config key '{key}' for server "
                        f"'{snapshot.server_name}'. Secrets should not be stored in plaintext."
                    ),
                    evidence=f"{key}: {_redact(value)}",
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
                        f"No plaintext secrets detected in configuration for server "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings
