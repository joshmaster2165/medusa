"""SM006: Shared Secrets Across Environments.

Detects MCP server deployments that use the same secrets across multiple environments such as
development, staging, and production. Shared secrets mean that a compromise in a less-secure
environment directly compromises production.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from medusa.checks.credential_exposure.cred001_secrets_in_config import _flatten_config
from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status

# Detect environment indicators within the same config
_MULTI_ENV_RE = re.compile(r"\b(dev|staging|stage|prod|production|test|uat)\b", re.IGNORECASE)
_SECRET_KEY_RE = re.compile(r"(password|secret|token|api[_-]?key|credential)", re.IGNORECASE)


class SharedSecretsAcrossEnvironmentsCheck(BaseCheck):
    """Shared Secrets Across Environments."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        if not snapshot.config_raw:
            return []

        # Collect secret values keyed by the env-label prefix of the config key
        env_values: dict[str, set[str]] = {}
        for key, value in _flatten_config(snapshot.config_raw):
            if not value or not _SECRET_KEY_RE.search(key):
                continue
            m = _MULTI_ENV_RE.search(key)
            env_label = m.group(1).lower() if m else "default"
            env_values.setdefault(env_label, set()).add(value)

        # Check for identical secret values across different env labels
        seen_vals: dict[str, str] = {}
        shared: list[tuple[str, str, str]] = []
        for env_label, values in env_values.items():
            for val in values:
                if val in seen_vals and seen_vals[val] != env_label:
                    shared.append((val, seen_vals[val], env_label))
                else:
                    seen_vals[val] = env_label

        if shared:
            return [
                Finding(
                    check_id=meta.check_id,
                    check_title=meta.title,
                    status=Status.FAIL,
                    severity=meta.severity,
                    server_name=snapshot.server_name,
                    server_transport=snapshot.transport_type,
                    resource_type="config",
                    resource_name=snapshot.config_file_path or "config",
                    status_extended=(
                        f"Same secret value appears in multiple environment configs for server "
                        f"'{snapshot.server_name}'. Secrets should be unique per environment."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            ]

        return [
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
                    f"No shared secrets across environments detected for server "
                    f"'{snapshot.server_name}'."
                ),
                remediation=meta.remediation,
                owasp_mcp=meta.owasp_mcp,
            )
        ]
