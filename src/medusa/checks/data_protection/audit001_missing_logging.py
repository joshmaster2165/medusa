"""AUDIT-001: Detect missing logging configuration in MCP servers.

Walks the server's ``config_raw`` looking for logging-related keys and
checks environment variables for logging/observability settings. If neither
source contains any logging configuration, the check fails.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from medusa.core.check import BaseCheck, ServerSnapshot
from medusa.core.models import CheckMetadata, Finding, Status
from medusa.utils.pattern_matching import LOGGING_CONFIG_KEYS, LOGGING_ENV_VARS


class MissingLoggingCheck(BaseCheck):
    """Check for missing logging configuration."""

    def metadata(self) -> CheckMetadata:
        meta_path = Path(__file__).with_suffix(".metadata.yaml")
        data = yaml.safe_load(meta_path.read_text())
        return CheckMetadata(**data)

    async def execute(self, snapshot: ServerSnapshot) -> list[Finding]:
        meta = self.metadata()
        findings: list[Finding] = []

        found_config_key = False
        found_env_var = False

        # Walk config_raw recursively looking for logging keys
        if snapshot.config_raw:
            found_config_key = _walk_config_for_logging_keys(snapshot.config_raw)

        # Check environment variables
        if snapshot.env:
            for env_var in snapshot.env:
                if env_var.upper() in LOGGING_ENV_VARS:
                    found_env_var = True
                    break

        if not found_config_key and not found_env_var:
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
                        f"Server '{snapshot.server_name}' has no logging "
                        f"configuration in config_raw or environment variables."
                    ),
                    evidence=(
                        f"config_raw keys checked: {bool(snapshot.config_raw)}, "
                        f"env vars checked: {len(snapshot.env)}"
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )
        else:
            sources: list[str] = []
            if found_config_key:
                sources.append("config_raw")
            if found_env_var:
                sources.append("environment variables")
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
                        f"Logging configuration detected in: "
                        f"{', '.join(sources)}."
                    ),
                    remediation=meta.remediation,
                    owasp_mcp=meta.owasp_mcp,
                )
            )

        return findings


def _walk_config_for_logging_keys(config: Any, _depth: int = 0) -> bool:
    """Recursively walk a config dict looking for logging-related keys."""
    if _depth > 10:
        return False
    if isinstance(config, dict):
        for key in config:
            if isinstance(key, str) and key.lower() in LOGGING_CONFIG_KEYS:
                return True
            if _walk_config_for_logging_keys(config[key], _depth + 1):
                return True
    elif isinstance(config, list):
        for item in config:
            if _walk_config_for_logging_keys(item, _depth + 1):
                return True
    return False
