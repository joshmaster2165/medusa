"""SM014: Secrets in Log Output.

Detects MCP servers that include secrets in log output, whether in application logs, access
logs, error logs, or debug logs. Logged secrets are exposed to anyone with log access and
persist in log storage systems indefinitely.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Config keys that control verbose/debug logging which may expose secrets
_RISKY_LOG_RE = re.compile(
    r"\b(log[_-]?(secrets|credentials|tokens|passwords|headers|request|body|full)|"
    r"debug[_-]?logging|verbose[_-]?logging|log[_-]?level)\b",
    re.IGNORECASE,
)
_RISKY_LOG_KEYS = {
    "log_secrets",
    "log_credentials",
    "log_tokens",
    "log_passwords",
    "log_headers",
    "log_request_body",
    "debug_logging",
    "verbose_logging",
}


class SecretsInLogsCheck(BaseCheck):
    """Secrets in Log Output."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        if snapshot.config_raw:
            for key, value in _flatten_config(snapshot.config_raw):
                leaf = key.split(".")[-1].split("[")[0].lower()
                # Flag if log key is risky AND value is truthy
                if leaf in _RISKY_LOG_KEYS or _RISKY_LOG_RE.search(key):
                    if value.lower() in {"true", "1", "yes", "debug", "verbose"}:
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
                                    f"Risky log setting '{key}={value}' detected for server "
                                    f"'{snapshot.server_name}'. Secrets may be exposed in logs."
                                ),
                                evidence=f"{key}={value}",
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
                        f"No risky log settings that could expose secrets for server "
                        f"'{snapshot.server_name}'."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        return findings
